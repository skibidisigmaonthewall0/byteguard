package com.obftest.mod.generator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Generates 100+ obfuscated short-named classes (a.java, b.java, etc.) inside testmod source tree.
 */
public class ClassGenerator {

    public static void main(String[] args) throws Exception {
        File outDir = new File("src/main/java/a/b/c");
        if (!outDir.exists()) outDir.mkdirs();

        String[] shortNames = {
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
            "aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj", "ak", "al", "am", "an", "ao", "ap", "aq", "ar", "as", "at", "au", "av", "aw", "ax", "ay", "az",
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "y0", "y1", "y2", "y3", "y4", "y5", "y6", "y7", "y8", "y9",
            "z0", "z1", "z2", "z3", "z4", "z5", "z6", "z7", "z8", "z9", "m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7", "m8", "m9",
            "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"
        };

        for (String className : shortNames) {
            File f = new File(outDir, className + ".java");
            try (PrintWriter pw = new PrintWriter(new FileWriter(f))) {
                pw.println("package a.b.c;");
                pw.println();
                pw.println("/** SCANNER TRIGGER: Short obfuscated class name and synthetic methods */");
                pw.println("public class " + className + " {");
                pw.println("    // Dummy bytes");
                pw.println("    public static final byte[] DUMMY_BYTES = new byte[] {0x1, 0x2, 0x3, 0x4, 0x5};");
                pw.println();
                pw.println("    public static void synthetic$0() {");
                pw.println("        // Dead synthetic method");
                pw.println("    }");
                pw.println("}");
            }
        }
        System.out.println("Generated " + shortNames.length + " classes.");
    }
}
