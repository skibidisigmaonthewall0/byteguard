package com.antirat.mod.metadata;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Handles mod metadata extraction from JAR files (fabric.mod.json, mcmod.info)
 * and resolves calling mod identities from Java stack trace frames.
 */
public class ModMetadata {
    private final String modId;
    private final String name;
    private final String version;
    private final File jarFile;
    private boolean hasEntrypoint = false;

    public ModMetadata(String modId, String name, String version, File jarFile) {
        this.modId = modId != null ? modId : (jarFile != null ? jarFile.getName() : "unknown");
        this.name = name != null ? name : this.modId;
        this.version = version != null ? version : "1.0.0";
        this.jarFile = jarFile;
    }

    public String getModId() {
        return modId;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public File getJarFile() {
        return jarFile;
    }

    public boolean hasEntrypoint() {
        return hasEntrypoint;
    }

    /**
     * Extracts metadata from a mod JAR file. Reads fabric.mod.json or mcmod.info if present.
     */
    public static ModMetadata fromJar(File jarFile) {
        if (jarFile == null || !jarFile.exists() || !jarFile.getName().endsWith(".jar")) {
            return new ModMetadata("unknown", jarFile != null ? jarFile.getName() : "Unknown File", "1.0.0", jarFile);
        }

        String modId = null;
        String name = null;
        String version = null;
        boolean hasEP = false;

        try (ZipFile zip = new ZipFile(jarFile)) {
            ZipEntry fabricEntry = zip.getEntry("fabric.mod.json");
            if (fabricEntry != null) {
                try (InputStream is = zip.getInputStream(fabricEntry);
                     InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                    JsonObject obj = JsonParser.parseReader(reader).getAsJsonObject();
                    if (obj.has("id")) modId = obj.get("id").getAsString();
                    if (obj.has("name")) name = obj.get("name").getAsString();
                    if (obj.has("version")) version = obj.get("version").getAsString();
                    try {
                        hasEP = obj.has("entrypoints") && !obj.get("entrypoints").getAsJsonObject().entrySet().isEmpty();
                    } catch (Exception ignored) {}
                }
            } else {
                ZipEntry mcmodEntry = zip.getEntry("mcmod.info");
                if (mcmodEntry != null) {
                    try (InputStream is = zip.getInputStream(mcmodEntry);
                         InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                        String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                        if (content.contains("\"modid\"")) {
                            int idx = content.indexOf("\"modid\"");
                            int start = content.indexOf("\"", idx + 7) + 1;
                            int end = content.indexOf("\"", start);
                            if (start > 0 && end > start) modId = content.substring(start, end);
                        }
                        if (content.contains("\"name\"")) {
                            int idx = content.indexOf("\"name\"");
                            int start = content.indexOf("\"", idx + 6) + 1;
                            int end = content.indexOf("\"", start);
                            if (start > 0 && end > start) name = content.substring(start, end);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }

        if (modId == null) modId = jarFile.getName().replace(".jar", "");
        if (name == null) name = modId;

        ModMetadata meta = new ModMetadata(modId, name, version, jarFile);
        meta.hasEntrypoint = hasEP;
        return meta;
    }


    /**
     * Inspects the current stack trace to identify which mod is initiating an action.
     */
    public static String identifyCallerMod() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            // Skip core Java, Fabric, Anti-RAT, and Mixin internal frames
            if (className.startsWith("java.") || className.startsWith("javax.") ||
                className.startsWith("sun.") || className.startsWith("jdk.") ||
                className.startsWith("com.antirat.") || className.startsWith("net.fabricmc.") ||
                className.startsWith("net.minecraft.") || className.startsWith("org.spongepowered.")) {
                continue;
            }

            // Extract package/class top level as mod indicator
            String[] parts = className.split("\\.");
            if (parts.length >= 2) {
                return parts[0] + "." + parts[1];
            }
            return className;
        }
        return "Unknown Mod";
    }
}
