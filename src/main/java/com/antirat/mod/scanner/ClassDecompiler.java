package com.antirat.mod.scanner;

import org.benf.cfr.reader.api.*;
import org.jetbrains.java.decompiler.main.decompiler.BaseDecompiler;
import org.jetbrains.java.decompiler.main.extern.IFernflowerLogger;
import org.jetbrains.java.decompiler.main.extern.IResultSaver;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.Manifest;
import java.util.zip.*;

/**
 * ClassDecompiler — Bundles CFR & Vineflower for in-app source-level inspection.
 *
 * Given a JAR file and a class entry path, decompiles it to human-readable Java
 * source and returns it as a String for display in the ByteGuard UI.
 *
 * CFR runs first (very fast, most reliable for obfuscated code).
 * Vineflower runs as fallback (better output for complex/Kotlin code).
 */
public class ClassDecompiler {

    public enum Engine { CFR, VINEFLOWER }

    public static class DecompileResult {
        public final String source;
        public final Engine engine;
        public final boolean success;
        public final String error;

        private DecompileResult(String source, Engine engine, boolean success, String error) {
            this.source = source;
            this.engine = engine;
            this.success = success;
            this.error = error;
        }

        public static DecompileResult ok(String source, Engine engine) {
            return new DecompileResult(source, engine, true, null);
        }

        public static DecompileResult fail(String error) {
            return new DecompileResult(null, null, false, error);
        }
    }

    /**
     * Decompile a specific .class entry from a JAR.
     * Tries CFR first, falls back to Vineflower.
     *
     * @param jarFile   The JAR file to extract from
     * @param classPath The internal ZIP path (e.g. "com/example/Payload.class")
     * @return DecompileResult with source or error message
     */
    public static DecompileResult decompile(File jarFile, String classPath) {
        // Try CFR first — fastest, handles obfuscated code well
        try {
            String result = decompileWithCFR(jarFile, classPath);
            if (result != null && !result.isBlank()) {
                return DecompileResult.ok(result, Engine.CFR);
            }
        } catch (Exception ignored) {}

        // Fallback to Vineflower — better for complex/Kotlin patterns
        try {
            String result = decompileWithVineflower(jarFile, classPath);
            if (result != null && !result.isBlank()) {
                return DecompileResult.ok(result, Engine.VINEFLOWER);
            }
        } catch (Exception vfEx) {
            return DecompileResult.fail("Both CFR and Vineflower failed: " + vfEx.getMessage());
        }

        return DecompileResult.fail("Decompilation returned empty output.");
    }

    // ── CFR ─────────────────────────────────────────────────────────────────

    private static String decompileWithCFR(File jarFile, String classPath) throws Exception {
        final StringBuilder output = new StringBuilder();

        CfrDriver driver = new CfrDriver.Builder()
            .withOptions(Map.of(
                "showversion", "false",
                "silent", "true",
                "comments", "false"
            ))
            .withOutputSink(new OutputSinkFactory() {
                @Override
                public List<SinkClass> getSupportedSinks(SinkType sinkType, Collection<SinkClass> available) {
                    return List.of(SinkClass.STRING);
                }

                @Override
                @SuppressWarnings("unchecked")
                public <T> Sink<T> getSink(SinkType sinkType, SinkClass sinkClass) {
                    if (sinkType == SinkType.JAVA) {
                        return (Sink<T>) (Sink<String>) s -> output.append(s);
                    }
                    return ignored -> {};
                }
            })
            .build();

        // CFR takes "path/to/file.jar!/com/example/Foo.class" format
        driver.analyse(List.of(jarFile.getAbsolutePath() + "!/" + classPath));
        return output.toString();
    }

    // ── Vineflower ──────────────────────────────────────────────────────────

    private static String decompileWithVineflower(File jarFile, String classPath) throws Exception {
        // Extract the target .class file to a temp dir (Vineflower needs a file on disk)
        Path tempInputDir  = Files.createTempDirectory("byteguard-vf-in-");
        Path tempOutputDir = Files.createTempDirectory("byteguard-vf-out-");

        try {
            // Extract class into temp input dir preserving package structure
            try (ZipFile zip = new ZipFile(jarFile)) {
                ZipEntry entry = zip.getEntry(classPath);
                if (entry == null) throw new IOException("Class not found in JAR: " + classPath);

                File outFile = tempInputDir.resolve(classPath).toFile();
                outFile.getParentFile().mkdirs();
                try (InputStream is = zip.getInputStream(entry);
                     OutputStream os = new FileOutputStream(outFile)) {
                    is.transferTo(os);
                }
            }

            // Collect decompiled output via IResultSaver
            final Map<String, String> results = new HashMap<>();

            IResultSaver saver = new IResultSaver() {
                @Override public void saveClassFile(String path, String archiveName, String qualifiedName, String entryName, int[] mapping) {}
                @Override public void saveClassEntry(String path, String archiveName, String qualifiedName, String entryName, String content) {
                    results.put(entryName, content);
                }
                @Override public void saveClassEntry(String path, String archiveName, String qualifiedName, String entryName, String content, int[] mapping) {
                    results.put(entryName, content);
                }
                // Unused stubs
                @Override public void saveFolder(String path) {}
                @Override public void copyFile(String source, String path, String entryName) {}
                @Override public void createArchive(String path, String archiveName, Manifest manifest) {}
                @Override public void saveDirEntry(String path, String archiveName, String entryName) {}
                @Override public void copyEntry(String source, String path, String archiveName, String entryName) {}
                @Override public void closeArchive(String path, String archiveName) {}
                @Override public void close() {}
                @Override public byte[] getCodeLineData(int[] multiline) { return null; }
            };

            IFernflowerLogger silentLogger = new IFernflowerLogger() {
                @Override public void writeMessage(String message, Severity severity) {}
                @Override public void writeMessage(String message, Severity severity, Throwable t) {}
            };

            Map<String, Object> options = new HashMap<>();
            options.put("log", "WARN");

            BaseDecompiler decompiler = new BaseDecompiler(saver, options, silentLogger);
            decompiler.addSource(tempInputDir.toFile());
            decompiler.decompileContext();

            // Find result — Vineflower uses .java extension
            String javaKey = classPath.replace(".class", ".java");
            // Try full path key, then just filename
            String content = results.get(javaKey);
            if (content == null) {
                content = results.values().stream().findFirst().orElse(null);
            }
            return content;

        } finally {
            deleteRecursive(tempInputDir.toFile());
            deleteRecursive(tempOutputDir.toFile());
        }
    }

    private static void deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) for (File c : children) deleteRecursive(c);
        }
        f.delete();
    }
}
