package com.antirat.mod.scanner;

import com.antirat.mod.metadata.ModMetadata;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Native Java Port of the Jarscanner JS Engine.
 * Runs exact Jarscanner logic, category risk weights, and domain blacklists,
 * producing a JarscannerReport that is compared against ByteGuard's scanner.
 */
public class JarscannerEngine {

    public static class JarscannerReport {
        public int finalScore = 0;
        public final Set<String> detections = new LinkedHashSet<>();
        public final List<String> webhooks = new ArrayList<>();
        public final List<String> blacklistedDomains = new ArrayList<>();
        public final List<String> suspiciousApis = new ArrayList<>();
        public String detectedObfuscator = null;
        public Map<String, Integer> categoryScores = new HashMap<>();
    }

    // ── Jarscanner Data Structures ──────────────────────────────────────────

    private static final Map<String, String> DESCRIPTIONS = Map.ofEntries(
        Map.entry("Curium", "Stealer / RAT"),
        Map.entry("Synapse", "Web Based Credential Stealer"),
        Map.entry("WeedHack", "Stealer targeting accounts"),
        Map.entry("NameProtect", "Stealer / RAT with RCE capabilities"),
        Map.entry("Void", "MaaS Stealer"),
        Map.entry("Adamrat", "Stealer targeting accounts"),
        Map.entry("Vanta", "Stealer targeting accounts"),
        Map.entry("Silentnet", "Stealer / RAT with RCE capabilities"),
        Map.entry("NiggaWare", "Credential stealer targeting gaming accounts"),
        Map.entry("SilentRaven", "Minecraft Token Stealer via Telegram Bots"),
        Map.entry("MicroStealer", "Infostealer targeting Discord tokens"),
        Map.entry("SessionStealer", "Targets Minecraft tokens"),
        Map.entry("TelegramController", "Uses Telegram Bot API for exfiltration"),
        Map.entry("Native Library (DLL)", "JAR contains Windows DLL (JNI)"),
        Map.entry("Java Agent (Persistence)", "Configured as Java Agent"),
        Map.entry("Woolexa", "Stealer targeting accounts"),
        Map.entry("GhostZ", "MaaS targeting accounts and credentials"),
        Map.entry("JRat", "Remote Access Trojan"),
        Map.entry("VisoRat", "Remote Access Trojan / Stealer")
    );

    private static final Map<String, String> DANGEROUS_APIS = Map.ofEntries(
        Map.entry("ihook", "Webhook signaling"),
        Map.entry("ProcessBuilder", "Command execution"),
        Map.entry("Runtime.getRuntime().exec", "Classic command execution"),
        Map.entry("Dropper", "Downloads external payload"),
        Map.entry("java.lang.ProcessBuilder", "Executes external programs"),
        Map.entry("java.awt.Robot", "Screenshots/mouse control"),
        Map.entry("java.awt.Robot.createScreenCapture", "Screen capture"),
        Map.entry("javax.sound.sampled", "Audio recording"),
        Map.entry("java.net.NetworkInterface.getNetworkInterfaces", "MAC address scanning"),
        Map.entry("System.getenv", "Environment variables"),
        Map.entry("System.getProperties", "OS / system info"),
        Map.entry("Clipboard.getData", "Clipboard access"),
        Map.entry("java.net.Socket", "Raw socket connection"),
        Map.entry("java.net.ServerSocket", "Opens network port"),
        Map.entry("ClassLoader.defineClass", "Loads hidden code from memory"),
        Map.entry("URLClassLoader", "Downloads & executes code"),
        Map.entry("java.nio.file.Files.write", "Writes files to disk"),
        Map.entry("net.minecraft.client.util.Session", "Minecraft Session ID access"),
        Map.entry("pastebin.com", "Hosts raw code/payloads"),
        Map.entry("com.mojang.authlib", "Mojang auth interaction"),
        Map.entry("net.minecraft.client.Minecraft.getInstance().getSession()", "Session token access")
    );

    private static final List<String> BLACKLIST_DOMAINS = List.of(
        "grabify.link", "niggaware", "ihook", "iplogger.org", "blasze.com", "fabric-api.one", "my-xarid.com", "tonapi.io",
        "ip-tracker.org", "whatismyipaddress.com", "db-ip.com", "api.ipify.org",
        "webhook.site", "pipedream.net", "requestbin.com", "transfer.sh", "telegram.org", "t.me",
        "anonfiles.com", "gofile.io", "file.io",
        "ghostbin.co", "rentry.co",
        "ngrok.io", "portmap.io", "localtunnel.me", "serveo.net",
        "checkip.amazonaws.com", "ipv4.icanhazip.com"
    );

    private static final Map<String, Integer> RISK_WEIGHTS = Map.ofEntries(
        Map.entry("MALWARE_MATCH", 100),
        Map.entry("JAVA_AGENT", 90),
        Map.entry("WEBHOOK", 80),
        Map.entry("NATIVE_DLL", 60),
        Map.entry("EXE", 80),
        Map.entry("OBFUSCATION", 50),
        Map.entry("SUSPICIOUS_API", 20),
        Map.entry("HIGH_ENTROPY", 20),
        Map.entry("ProcessBuilder", 60),
        Map.entry("Base64", 0),
        Map.entry("Dropper", 10)
    );

    private static final Map<String, Integer> CATEGORY_CAPS = Map.of(
        "MALWARE", 100,
        "OBFUSCATION", 40,
        "PROCESS_BUILDER", 30,
        "WEBHOOK", 100,
        "NATIVE", 60,
        "DOMAIN", 50,
        "SUSPICIOUS_API", 30,
        "DROPPER", 30
    );

    private static final Pattern PAT_DISCORD_WEBHOOK = Pattern.compile("(?:https?://)?discord\\.com/api/webhooks/[a-zA-Z0-9/_#-]+");
    private static final Pattern PAT_TELEGRAM_TOKEN = Pattern.compile("\\b[0-9]{8,11}:[A-Za-z0-9_-]{35}\\b");
    private static final Pattern PAT_URL = Pattern.compile("https?://[^\\s\"'`>]+");
    private static final Pattern PAT_B64 = Pattern.compile("([A-Za-z0-9+/]{40,}={0,2})");

    private static final Pattern KNOWN_NATIVE_JNA = Pattern.compile("(^|/)(win32-x86(-64)?|win32-aarch64|linux-x86(-64)?|linux-arm(64)?|darwin(-(x86-64|aarch64))?|freebsd-x86(-64)?|sunos-(x86|sparc(v9)?)|aix-ppc(64)?)/", Pattern.CASE_INSENSITIVE);
    private static final Pattern KNOWN_NATIVE_LWJGL = Pattern.compile("(^|/)(windows|linux|macos|freebsd|openbsd|solaris)/(x64|x86|arm32|arm64|aarch64|riscv64|loongarch64|ppc64le|mips64el)(/|$)", Pattern.CASE_INSENSITIVE);

    private static boolean isKnownNativeLibPath(String path) {
        return KNOWN_NATIVE_JNA.matcher(path).find() ||
               KNOWN_NATIVE_LWJGL.matcher(path).find() ||
               path.contains("com/sun/jna/") || path.contains("/jna/") || path.contains("org/lwjgl/");
    }

    // ── Jarscanner Scanner Implementation ───────────────────────────────────

    public static JarscannerReport scanJar(File jarFile) {
        JarscannerReport report = new JarscannerReport();
        if (jarFile == null || !jarFile.exists()) return report;

        Map<String, Integer> catScores = new HashMap<>();
        catScores.put("MALWARE", 0);
        catScores.put("OBFUSCATION", 0);
        catScores.put("PROCESS_BUILDER", 0);
        catScores.put("WEBHOOK", 0);
        catScores.put("NATIVE", 0);
        catScores.put("DOMAIN", 0);
        catScores.put("SUSPICIOUS_API", 0);
        catScores.put("DROPPER", 0);

        boolean nativeScored = false;
        boolean processBuilderFlagged = false;

        try (ZipFile zip = new ZipFile(jarFile)) {
            List<String> files = new ArrayList<>();
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                files.add(entries.nextElement().getName());
            }

            // 1. Direct File Structure Checks
            if (zip.getEntry("com/woolexa/MinecraftModClient.class") != null) { report.detections.add("Woolexa"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("fabric.api.json") != null)                      { report.detections.add("WeedHack"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("cfg.json") != null)                             { report.detections.add("NameProtect"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("lang.dat") != null)                             { report.detections.add("Silentnet"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("META-INF/a1b2c3d4") != null)                    { report.detections.add("Adamrat"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("curium.cfg") != null)                           { report.detections.add("Curium"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("9c75c089b05533ed.txt") != null)                 { report.detections.add("Vanta"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("void.accesswidener") != null)                   { report.detections.add("Void"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
            if (zip.getEntry("META-INF/jars/7059873d.jar") != null)          { report.detections.add("GhostZ"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }

            for (String f : files) {
                if (f.contains("SilentRaven")) { report.detections.add("SilentRaven"); catScores.put("MALWARE", 100); }
            }

            // Obfuscation check
            List<String> classes = files.stream().filter(f -> f.endsWith(".class")).toList();
            boolean isShortNameObf = classes.size() > 5 && classes.stream().filter(f -> {
                String simple = f.contains("/") ? f.substring(f.lastIndexOf('/') + 1) : f;
                return simple.length() < 4;
            }).count() / (double) classes.size() > 0.4;

            Pattern barcodeRegex = Pattern.compile("^[Il10O]+$");
            boolean isBarcodeObf = classes.stream().anyMatch(f -> {
                String simple = f.contains("/") ? f.substring(f.lastIndexOf('/') + 1).replace(".class", "") : f.replace(".class", "");
                return barcodeRegex.matcher(simple).matches();
            });

            if (isShortNameObf || isBarcodeObf) {
                catScores.put("OBFUSCATION", catScores.get("OBFUSCATION") + 50);
                if (isBarcodeObf) report.detectedObfuscator = "Barcode Obfuscation";
            }

            // File Content Analysis
            for (String path : files) {
                ZipEntry entry = zip.getEntry(path);
                if (entry == null || entry.isDirectory()) continue;

                String pathLower = path.toLowerCase();
                if (pathLower.endsWith(".dll") || pathLower.endsWith(".exe")) {
                    report.detections.add("Native Library / Executable: " + path);
                    if (!isKnownNativeLibPath(path) && !nativeScored) {
                        catScores.put("NATIVE", catScores.get("NATIVE") + (pathLower.endsWith(".exe") ? 80 : 60));
                        nativeScored = true;
                    }
                }

                if (pathLower.endsWith(".class") || pathLower.endsWith(".json") || pathLower.endsWith(".mf") || pathLower.endsWith(".cfg") || pathLower.endsWith(".txt")) {
                    if (entry.getSize() > 600_000) continue;

                    try (InputStream is = zip.getInputStream(entry)) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
                        String text = baos.toString(StandardCharsets.ISO_8859_1);

                        if (path.endsWith("MANIFEST.MF") && (text.contains("Premain-Class") || text.contains("Agent-Class"))) {
                            report.detections.add("Java Agent (Persistence)");
                            catScores.put("MALWARE", catScores.get("MALWARE") + 90);
                        }

                        Matcher mHook = PAT_DISCORD_WEBHOOK.matcher(text);
                        while (mHook.find()) {
                            String hook = mHook.group();
                            report.detections.add("Discord Webhook");
                            report.webhooks.add(hook);
                            catScores.put("WEBHOOK", catScores.get("WEBHOOK") + 80);
                        }

                        if (text.contains("api.telegram.org") || PAT_TELEGRAM_TOKEN.matcher(text).find()) {
                            report.detections.add("TelegramController");
                            catScores.put("WEBHOOK", Math.max(catScores.get("WEBHOOK"), 90));
                        }

                        Matcher mUrl = PAT_URL.matcher(text);
                        while (mUrl.find()) {
                            String urlStr = mUrl.group();
                            for (String domain : BLACKLIST_DOMAINS) {
                                if (urlStr.toLowerCase().contains(domain)) {
                                    report.detections.add("Blacklisted Exfiltration Domain: " + domain);
                                    report.blacklistedDomains.add(urlStr);
                                    catScores.put("DOMAIN", catScores.get("DOMAIN") + 50);
                                    break;
                                }
                            }
                        }

                        for (Map.Entry<String, String> api : DANGEROUS_APIS.entrySet()) {
                            if (text.contains(api.getKey())) {
                                report.suspiciousApis.add(api.getKey() + " (" + api.getValue() + ")");
                                catScores.put("SUSPICIOUS_API", catScores.get("SUSPICIOUS_API") + 20);
                            }
                        }

                        if ((text.contains("ProcessBuilder") || text.contains("processbuilder")) && !processBuilderFlagged) {
                            catScores.put("PROCESS_BUILDER", catScores.get("PROCESS_BUILDER") + 60);
                            processBuilderFlagged = true;
                        }

                        if (text.contains("ur.erawaggin") || text.contains("niggaware.ru")) { report.detections.add("NiggaWare"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }
                        if (text.contains("bambooware"))   { report.detections.add("BambooWare"); catScores.put("MALWARE", catScores.get("MALWARE") + 100); }

                    } catch (Exception ignored) {}
                }
            }

        } catch (Exception ignored) {}

        // Calculate Category Cap Score
        int totalScore = 0;
        for (Map.Entry<String, Integer> entry : catScores.entrySet()) {
            int capped = Math.min(entry.getValue(), CATEGORY_CAPS.getOrDefault(entry.getKey(), 100));
            totalScore += capped;
        }

        report.categoryScores = catScores;
        report.finalScore = Math.min(totalScore, 100);
        return report;
    }
}
