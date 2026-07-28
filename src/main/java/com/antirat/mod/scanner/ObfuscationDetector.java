package com.antirat.mod.scanner;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Advanced Obfuscation Detection engine computing heuristics and score (0-100).
 */
public class ObfuscationDetector {

    public static class ObfuscationResult {
        public final int score; // 0 (Clean) to 100 (Severely Obfuscated)
        public final List<String> reasons;

        public ObfuscationResult(int score, List<String> reasons) {
            this.score = Math.min(100, Math.max(0, score));
            this.reasons = reasons;
        }
    }

    public static ObfuscationResult analyzeJar(File jarFile) {
        int totalScore = 0;
        List<String> reasons = new ArrayList<>();

        if (jarFile == null || !jarFile.exists()) {
            return new ObfuscationResult(0, List.of("Invalid file"));
        }

        int totalClasses = 0;
        int shortNamedClasses = 0;
        int syntheticMethodsCount = 0;
        int totalMethods = 0;
        int reflectionUsageCount = 0;
        int totalStrings = 0;
        int highEntropyStrings = 0;
        int unreadableStrings = 0;
        boolean missingMetadata = true;
        boolean hasPackedResources = false;

        try (ZipFile zip = new ZipFile(jarFile)) {
            // Check metadata presence
            if (zip.getEntry("fabric.mod.json") != null || zip.getEntry("mcmod.info") != null) {
                missingMetadata = false;
            }

            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                // Check packed / resource compression indicators
                if (name.endsWith(".pack") || name.endsWith(".encrypted") || name.contains("flattened") || name.endsWith(".lzma")) {
                    hasPackedResources = true;
                }

                if (name.endsWith(".class")) {
                    totalClasses++;
                    String className = name.substring(0, name.length() - 6);
                    String simpleName = className.contains("/") ? className.substring(className.lastIndexOf("/") + 1) : className;

                    // Heuristic: Short class names (e.g. "a", "b", "c")
                    if (simpleName.length() <= 2) {
                        shortNamedClasses++;
                    }

                    try (InputStream is = zip.getInputStream(entry)) {
                        byte[] classBytes = is.readAllBytes();
                        ClassReader reader = new ClassReader(classBytes);
                        ClassNode cn = new ClassNode();
                        reader.accept(cn, ClassReader.SKIP_FRAMES);

                        for (MethodNode mn : cn.methods) {
                            totalMethods++;
                            if ((mn.access & org.objectweb.asm.Opcodes.ACC_SYNTHETIC) != 0) {
                                syntheticMethodsCount++;
                            }
                            if (mn.name.equals("invoke") || mn.name.contains("forName") || mn.name.contains("getDeclaredField")) {
                                reflectionUsageCount++;
                            }
                        }

                        // Inspect constant pool / fields for string entropy & readability
                        for (FieldNode fn : cn.fields) {
                            if (fn.value instanceof String str) {
                                totalStrings++;
                                double entropy = calculateEntropy(str);
                                if (entropy > 4.5 && str.length() > 8) {
                                    highEntropyStrings++;
                                }
                                if (!isReadableString(str) && str.length() > 4) {
                                    unreadableStrings++;
                                }
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception e) {
            reasons.add("Failed to parse JAR structure: " + e.getMessage());
            totalScore += 20;
        }

        // Evaluate Heuristics:

        // 1. Missing or minimal metadata
        if (missingMetadata) {
            totalScore += 20;
            reasons.add("Missing mod metadata (fabric.mod.json / mcmod.info missing)");
        }

        // 2. Short class names ratio (> 30% of classes have 1-2 char names)
        if (totalClasses > 0) {
            double shortRatio = (double) shortNamedClasses / totalClasses;
            if (shortRatio > 0.35) {
                totalScore += 30;
                reasons.add(String.format("Unusually short class names (%.1f%% of classes are obfuscated short names)", shortRatio * 100));
            }
        }

        // 3. High string entropy
        if (totalStrings > 5) {
            double entropyRatio = (double) highEntropyStrings / totalStrings;
            if (entropyRatio > 0.25) {
                totalScore += 25;
                reasons.add(String.format("High entropy encrypted strings detected (%.1f%% encrypted strings)", entropyRatio * 100));
            }
        }

        // 4. Unreadable strings ratio
        if (totalStrings > 5 && (double) unreadableStrings / totalStrings > 0.3) {
            totalScore += 15;
            reasons.add("High ratio of unreadable non-printable string constants");
        }

        // 5. Reflection density
        if (reflectionUsageCount > 5) {
            totalScore += 20;
            reasons.add("Heavy suspicious reflection usage (" + reflectionUsageCount + " reflection call points)");
        }

        // 6. Excessive synthetic methods (> 40%)
        if (totalMethods > 10) {
            double syntheticRatio = (double) syntheticMethodsCount / totalMethods;
            if (syntheticRatio > 0.4) {
                totalScore += 15;
                reasons.add(String.format("Excessive synthetic method ratio (%.1f%% synthetic)", syntheticRatio * 100));
            }
        }

        // 7. Resource packing / compression indicators
        if (hasPackedResources) {
            totalScore += 25;
            reasons.add("Packed / encrypted embedded resource archives detected");
        }

        if (reasons.isEmpty()) {
            reasons.add("Normal bytecode structure and metadata");
        }

        return new ObfuscationResult(totalScore, reasons);
    }

    /**
     * Shannon Entropy calculation for string randomness/encryption detection.
     */
    public static double calculateEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        int[] count = new int[256];
        for (char c : s.toCharArray()) {
            count[c & 0xFF]++;
        }
        double entropy = 0.0;
        double len = s.length();
        for (int c : count) {
            if (c > 0) {
                double p = c / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    private static boolean isReadableString(String s) {
        int printable = 0;
        for (char c : s.toCharArray()) {
            if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') {
                printable++;
            }
        }
        return (double) printable / s.length() >= 0.85;
    }
}
