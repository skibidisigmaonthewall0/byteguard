package com.obftest.mod.dummy;

/**
 * SCANNER TRIGGER: Dummy strings containing suspicious API names and token paths.
 * ALL CONSTANTS AND CODE IN THIS CLASS ARE COMPLETELY UNUSED DEAD CODE.
 */
public class FlaggedStrings {

    // SCANNER HEURISTIC: Suspicious API names & commands (Dead constants)
    public static final String S1 = "Runtime.exec";
    public static final String S2 = "ProcessBuilder";
    public static final String S3 = "launcher_accounts.json";
    public static final String S4 = "usercache.json";
    public static final String S5 = "cmd.exe";
    public static final String S6 = "powershell";
    public static final String S7 = "curl";
    public static final String S8 = "wget";
    public static final String S9 = "discord.com/api/webhooks/123456789/dummy_token";

    // SCANNER HEURISTIC: High Entropy Strings & Base64 constants (Harmless encoded text)
    public static final String BASE64_DUMMY = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBoYXJtbGVzcyB0ZXN0IHN0cmluZyBmb3IgYW50aXJhdCBzY2FubmVyLg==";
    public static final String HIGH_ENTROPY_1 = "k9X#mQ!8zP$wL2vN&jR4tY*bH6cF0gV5sA7dE1uI3oK9xZ";
    public static final String HIGH_ENTROPY_2 = "9fA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9";

    // SCANNER HEURISTIC: Dummy Unused Reflection References
    public static void dummyReflection() {
        if (System.currentTimeMillis() == 0) { // Never executed
            try {
                Class<?> c = Class.forName("java.lang.ProcessBuilder");
                c.getDeclaredMethod("start").invoke(null);
            } catch (Exception ignored) {
            }
        }
    }

    // SCANNER HEURISTIC: Artificial Control-Flow & Large Switch Statement
    public static int dummyComplexControlFlow(int input) {
        int x = input;
        switch (x) {
            case 1 -> x += 100;
            case 2 -> x += 200;
            case 3 -> x += 300;
            case 4 -> x += 400;
            case 5 -> x += 500;
            case 6 -> x += 600;
            case 7 -> x += 700;
            case 8 -> x += 800;
            case 9 -> x += 900;
            case 10 -> x += 1000;
            default -> x = 0;
        }
        return x;
    }
}
