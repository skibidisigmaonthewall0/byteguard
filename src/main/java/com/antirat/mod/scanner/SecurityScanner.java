package com.antirat.mod.scanner;

import com.antirat.mod.metadata.ModMetadata;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.io.File;
import java.io.InputStream;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Full-Spectrum Pre-launch Static Bytecode Security Scanner.
 *
 * Detects the following bypass categories:
 *
 * EXECUTION BYPASSES:
 *  - ProcessBuilder / Runtime.exec / ProcessHandle
 *  - Desktop.getDesktop().open() / browse() — exec without Runtime.exec
 *  - ScriptEngine / Nashorn / Graal JS eval
 *  - JNDI InitialContext.lookup() remote execution (Log4Shell-style)
 *  - MethodHandles.lookup().findVirtual() dynamic method calls
 *  - VirtualMachine.attach() / loadAgent() agent injection
 *  - Native JNI method declarations
 *
 * OBFUSCATION BYPASSES:
 *  - XOR decryption loops (IXOR opcode)
 *  - Arithmetic delta I2C string building
 *  - StringBuilder char-by-char append obfuscation
 *  - String split/join fragment reassembly
 *  - Base64 encoded string constants
 *  - Class.forName + Method.invoke reflective execution
 *  - Class.getMethod / getDeclaredMethod reflection
 *
 * DATA THEFT SIGNATURES:
 *  - Minecraft session token (getAccessToken, getSession)
 *  - launcher_accounts.json / launcher_profiles.json
 *  - usercache.json / usernamecache.json
 *  - Discord token file paths (Local Storage/leveldb)
 *  - Browser data paths (Chrome, Firefox, Edge user data)
 *  - Crypto wallet files (wallet.dat, .electrum, seed.txt)
 *  - Windows Credential Manager access
 *  - Discord webhook exfiltration URLs
 *
 * EVASION BYPASSES:
 *  - Thread.sleep / Timer / ScheduledExecutor delayed execution
 *  - System.getenv("WINDIR"/"APPDATA") path building
 *  - SecurityManager nullification
 *  - Unsafe.defineClass() / allocateMemory() direct memory
 *  - URLClassLoader / ClassLoader.loadClass() dynamic loading
 *  - ObjectInputStream.readObject() deserialization gadget chains
 *
 * SURVEILLANCE BYPASSES:
 *  - Robot.createScreenCapture() screen exfiltration
 *  - Toolkit.getSystemClipboard() clipboard hijack (crypto swap)
 *  - KeyboardFocusManager.addKeyEventDispatcher() keylogger
 *
 * STUB/EVASION:
 *  - Near-empty stub mod detection (declares entrypoints, almost no code)
 */
public class SecurityScanner {

    public enum SuspicionLevel {
        CLEAN("CLEAN",       0x00FF00),
        LOW("LOW",           0xFFFF00),
        MEDIUM("MEDIUM",     0xFF8800),
        HIGH("HIGH",         0xFF0000),
        CRITICAL("CRITICAL RAT", 0xFF0055);

        public final String label;
        public final int colorHex;

        SuspicionLevel(String label, int colorHex) {
            this.label = label;
            this.colorHex = colorHex;
        }
    }

    public static class SecurityReport {
        public final ModMetadata metadata;
        public final SuspicionLevel suspicionLevel;
        public final int suspicionScore;
        public final Set<String> detectedCapabilities;
        public final ObfuscationDetector.ObfuscationResult obfuscationResult;
        public final List<String> flaggedReasons;
        public final List<String> flaggedStrings;

        public SecurityReport(ModMetadata metadata, SuspicionLevel level, int score,
                              Set<String> capabilities, ObfuscationDetector.ObfuscationResult obfuscation,
                              List<String> reasons, List<String> flaggedStrings) {
            this.metadata = metadata;
            this.suspicionLevel = level;
            this.suspicionScore = score;
            this.detectedCapabilities = capabilities;
            this.obfuscationResult = obfuscation;
            this.flaggedReasons = reasons;
            this.flaggedStrings = flaggedStrings;
        }
    }

    // ── String-based threat signatures ──────────────────────────────────────

    /** Sensitive Minecraft / launcher account files */
    private static final String[] ACCOUNT_FILES = {
        "launcher_accounts.json", "launcher_profiles.json",
        "usercache.json", "usernamecache.json",
        "launcher_log.txt", "launcher_settings.json"
    };

    /** Discord token & data paths */
    private static final String[] DISCORD_PATHS = {
        "discord/local storage", "discord\\local storage",
        "local storage/leveldb", "local storage\\leveldb",
        "discordcanary", "discordptb", "storage.db",
        "discord/network", "storage/leveldb"
    };

    /** Browser credential / cookie paths */
    private static final String[] BROWSER_PATHS = {
        "google/chrome/user data", "google\\chrome\\user data",
        "mozilla/firefox/profiles", "mozilla\\firefox\\profiles",
        "microsoft/edge/user data", "microsoft\\edge\\user data",
        "opera software", "yandex/yandexbrowser",
        "/login data", "\\login data", "login data.sqlite",
        "/cookies", "\\cookies", "cookies.sqlite", "cookies-journal", "network/cookies",
        "/web data", "\\web data", "default/cookies"
    };

    /** Crypto wallet file paths */
    private static final String[] CRYPTO_PATHS = {
        "wallet.dat", ".electrum", "seed.txt", "keystore",
        "metamask", "bitcoin/wallet", "ethereum/keystore",
        "exodus/", "atomic wallet", "jaxx", "coinbase"
    };

    /** Shell / script execution strings */
    private static final String[] SHELL_STRINGS = {
        "powershell", "cmd.exe", "cmd /c", "bash", "sh -c",
        "calc.exe", "nc.exe", "ncat", "curl ", "wget ",
        "mshta", "wscript", "cscript", "regsvr32",
        "certutil", "bitsadmin", "rundll32", "msiexec",
        "/c echo", "invoke-expression", "iex(", "downloadstring"
    };

    /** Discord webhook exfil URL patterns */
    private static final String[] WEBHOOK_PATTERNS = {
        "discord.com/api/webhooks", "discordapp.com/api/webhooks",
        "ptb.discord.com/api/webhooks", "canary.discord.com/api/webhooks"
    };

    // ── Token & Webhook Regex Signatures ────────────────────────────────────
    private static final java.util.regex.Pattern PAT_DISCORD_WEBHOOK =
        java.util.regex.Pattern.compile("https?://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[A-Za-z0-9_-]+");

    private static final java.util.regex.Pattern PAT_DISCORD_BOT_TOKEN =
        java.util.regex.Pattern.compile("(?:mfa\\.[A-Za-z0-9_-]{84})|(?:[MNOG][A-Za-z0-9_-]{23,27}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,38})");

    private static final java.util.regex.Pattern PAT_TELEGRAM_BOT_TOKEN =
        java.util.regex.Pattern.compile("\\d{8,10}:[A-Za-z0-9_-]{35}");

    private static final java.util.regex.Pattern PAT_SLACK_WEBHOOK =
        java.util.regex.Pattern.compile("https?://hooks\\.slack\\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+");

    private static final java.util.regex.Pattern PAT_SLACK_TOKEN =
        java.util.regex.Pattern.compile("xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*");

    private static final java.util.regex.Pattern PAT_GUILDED_WEBHOOK =
        java.util.regex.Pattern.compile("https?://media\\.guilded\\.gg/webhooks/[a-f0-9-]+/[A-Za-z0-9_-]+");

    private static final java.util.regex.Pattern PAT_GUILDED_TOKEN =
        java.util.regex.Pattern.compile("gapi_[A-Za-z0-9]{64}");

    private static final java.util.regex.Pattern PAT_GENERIC_WEBHOOK =
        java.util.regex.Pattern.compile("https?://(?:webhook\\.site|pipedream\\.net|requestbin\\.com|hookdeck\\.com)/[a-zA-Z0-9_-]+");

    private static final java.util.regex.Pattern PAT_GITHUB_TOKEN =
        java.util.regex.Pattern.compile("(?:ghp_[A-Za-z0-9]{36})|(?:github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})");

    private static final java.util.regex.Pattern PAT_AWS_KEY =
        java.util.regex.Pattern.compile("AKIA[0-9A-Z]{16}");

    /** Minecraft session token access method names */
    private static final String[] SESSION_METHODS = {
        "getAccessToken", "getSession", "getProfile",
        "getToken", "getAuthToken", "getPlayerToken"
    };

    /** Windows/Linux persistence paths — startup folders, registry, cron */
    private static final String[] PERSISTENCE_PATHS = {
        // Windows Startup folder
        "microsoft\\windows\\start menu\\programs\\startup",
        "microsoft/windows/start menu/programs/startup",
        "appdata\\roaming\\microsoft\\windows\\start menu",
        // Windows Registry run keys
        "software\\microsoft\\windows\\currentversion\\run",
        "software\\microsoft\\windows\\currentversion\\runonce",
        "software\\wow6432node\\microsoft\\windows\\currentversion\\run",
        "hkey_current_user\\software\\microsoft\\windows\\currentversion\\run",
        "hkcu\\software\\microsoft\\windows\\currentversion\\run",
        // Scheduled Tasks
        "schtasks /create", "taskschd.msc", "\\tasks\\",
        // Linux persistence
        "/etc/cron.d/", "/etc/cron.daily/", "/etc/init.d/",
        "~/.bashrc", "~/.profile", "~/.config/autostart",
        "/systemd/system/", ".desktop\" exec=",
        // Java autostart
        "java.util.prefs", "vmd-gnu"
    };

    /** VM / sandbox evasion & anti-analysis strings */
    private static final String[] VM_EVASION_STRINGS = {
        // VMware fingerprinting
        "vmware", "vbox", "virtualbox", "virtual machine",
        "sandboxie", "wine\\", "qemu",
        // Hardware/CPU fingerprinting used to detect VMs
        "processor_identifier", "processor_level", "processor_revision",
        "hypervisor", "virt", "bochs", "xen",
        // Common AV/sandbox process names checked by malware
        "wireshark", "procmon", "procexp", "ollydbg", "x64dbg", "ida.exe",
        "fiddler", "charles", "burpsuite", "dnspy",
        // Timing-based evasion hints
        "totalphysicalmemory", "systeminfo", "wmic",
        // Java-specific VM detection
        "java.vm.vendor", "java.vm.name", "os.name",
        "user.name", "user.home", "user.dir"
    };

    /** Suspicious file write destination paths */
    private static final String[] SUSPICIOUS_WRITE_PATHS = {
        // Writing to appdata (dropper writing payload)
        "appdata\\roaming\\", "appdata\\local\\", "%appdata%",
        // Writing to temp (staging area)
        "\\temp\\", "/tmp/", "%temp%",
        // Writing executable files
        "system32\\", "syswow64\\",
        // Writing to minecraft mods dir from outside mod loader
        ".minecraft\\mods\\", ".minecraft/mods/",
        // Writing to startup (persistence)
        "\\startup\\", "/startup/"
    };

    // ────────────────────────────────────────────────────────────────────────


    public static SecurityReport scanJar(File jarFile) {
        ModMetadata meta = ModMetadata.fromJar(jarFile);
        Set<String> capabilities = new LinkedHashSet<>();
        List<String> reasons = new ArrayList<>();
        List<String> flaggedStrings = new ArrayList<>();
        List<String> matchedRules = new ArrayList<>();
        int score = 0;
        int totalClassCount = 0;
        int totalMethodCount = 0;

        // ── SELF-SCANNER WHITELIST: ByteGuard Scanning Itself ────────────────
        if (meta.getModId() != null && (meta.getModId().equalsIgnoreCase("byteguard") || meta.getModId().equalsIgnoreCase("antirat"))) {
            capabilities.add("ByteGuard Security Engine (Verified Clean)");
            return new SecurityReport(meta, SuspicionLevel.CLEAN, 0, capabilities, new ObfuscationDetector.ObfuscationResult(0, List.of()), reasons, flaggedStrings);
        }

        // ── USER MOD WHITELIST CHECK ─────────────────────────────────────────
        if (meta.getModId() != null && com.antirat.mod.manager.PermissionManager.isWhitelisted(meta.getModId())) {
            capabilities.add("Whitelisted User Mod (Verified 0/100 CLEAN)");
            return new SecurityReport(meta, SuspicionLevel.CLEAN, 0, capabilities, new ObfuscationDetector.ObfuscationResult(0, List.of()), reasons, flaggedStrings);
        }

        // ── THREAT DATABASE: SHA-256 hash + mod ID + dev/neko + Updater.class + Ethereum RPC ──
        ThreatDatabase.ThreatResult threat = ThreatDatabase.scanJar(jarFile, meta.getModId());
        score += threat.scoreAdded;

        if (threat.isKnownBadHash) {
            capabilities.add("!! SHA-256 MATCHES KNOWN MALWARE JAR: " + threat.hashMatchLabel);
            addReason("JAR SHA-256 hash matched known-bad database: " + threat.hashMatchLabel, reasons);
            flagStr("[HASH MATCH] " + threat.hashMatchLabel, flaggedStrings);
        }
        if (threat.isBlockedModId) {
            capabilities.add("!! BLOCKED MOD ID: " + meta.getModId() + " — " + threat.blockedIdLabel);
            addReason("Mod ID is on the blocked list: " + meta.getModId() + " — " + threat.blockedIdLabel, reasons);
        }
        if (threat.hasNekoPackage) {
            capabilities.add("!! Fractureiser dev/neko Package Detected (Stage 0)");
            for (String cls : threat.nekoClasses) {
                addReason("Fractureiser class found: " + cls, reasons);
                flagStr("[FRACTUREISER] " + cls, flaggedStrings);
            }
        }
        if (threat.hasUpdaterClass) {
            capabilities.add("Updater.class / Propagation Loader Detected (Fractureiser / Skyrage)");
            for (String cls : threat.updaterClasses) {
                addReason("Suspicious loader class: " + cls, reasons);
            }
        }
        if (threat.hasEthRpcDomain) {
            capabilities.add("!! EtherHiding C2 — Ethereum RPC Domain in Bytecode (WeedHack signature)");
            for (String domain : threat.ethDomains) {
                addReason("Ethereum RPC / EtherHiding C2 domain found: " + domain, reasons);
                flagStr("[ETH-RPC] " + domain, flaggedStrings);
            }
        }

        // 1. Obfuscation Heuristics
        ObfuscationDetector.ObfuscationResult obf = ObfuscationDetector.analyzeJar(jarFile);
        score += obf.score;
        if (obf.score >= 35) {
            capabilities.add("Obfuscated / Packed Bytecode (" + obf.score + "/100)");
            reasons.addAll(obf.reasons);
        }

        try (ZipFile zip = new ZipFile(jarFile)) {

            // ── JNI / Native Binary Scanner (.dll, .so, .dylib) ─────────────
            JniBinaryScanner.NativeScanResult nativeResult = JniBinaryScanner.scanNativeLibraries(zip);
            if (nativeResult.hasNativeBinary) {
                if (nativeResult.isSuspicious) {
                    capabilities.add("!! Suspicious Native JNI Binary Payload (.dll/.so/.dylib)");
                    for (String imp : nativeResult.detectedImports) {
                        addReason("Native binary import matched: " + imp, reasons);
                        flagStr("[NATIVE IMPORT] " + imp, flaggedStrings);
                    }
                    score += nativeResult.scoreAdded;
                } else {
                    // Plain native libraries (LWJGL, audio, etc.) are normal for graphics/sound mods
                    capabilities.add("Embedded Native Binary (.dll/.so/.dylib)");
                    // No score added — LWJGL, OpenAL, etc. are standard Minecraft dependencies
                }
            }

            // ── 2. MANIFEST.MF Analysis ──────────────────────────────────────
            ZipEntry manifest = zip.getEntry("META-INF/MANIFEST.MF");
            if (manifest != null) {
                try (InputStream mis = zip.getInputStream(manifest)) {
                    String mf = new String(mis.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).toLowerCase();
                    // Agent-Class / Premain-Class = Java agent dropper
                    if (mf.contains("agent-class:") || mf.contains("premain-class:")) {
                        capabilities.add("!! MANIFEST: Agent-Class / Premain-Class declared — Java agent dropper");
                        addReason("MANIFEST.MF declares Agent-Class or Premain-Class — mod can inject into any running JVM", reasons);
                        score += 90;
                    }
                    // Can-Redefine-Classes / Can-Retransform-Classes = bytecode rewriting
                    boolean isFabricMod = meta.getModId() != null && meta.getModId().startsWith("fabric-");
                    if ((mf.contains("can-redefine-classes: true") || mf.contains("can-retransform-classes: true")) && !isFabricMod) {
                        capabilities.add("MANIFEST: Can-Redefine/Retransform-Classes — runtime bytecode rewriting capability");
                        addReason("MANIFEST.MF declares bytecode rewriting permissions", reasons);
                        score += 60;
                    }
                    // Suspicious Main-Class in a mod (mods don't need Main-Class)
                    if (mf.contains("main-class:") && !mf.contains("net.fabricmc") && !mf.contains("cpw.mods")) {
                        capabilities.add("MANIFEST: Suspicious Main-Class in a Fabric mod (mods don't need this)");
                        addReason("MANIFEST.MF has Main-Class entry — may be a standalone dropper disguised as a mod", reasons);
                        score += 35;
                    }
                } catch (Exception ignored) {}
            }

            // ── META-INF/services deep scan ──────────────────────────────────
            Enumeration<? extends ZipEntry> svcEntries = zip.entries();
            while (svcEntries.hasMoreElements()) {
                ZipEntry svc = svcEntries.nextElement();
                String svcName = svc.getName();
                if (svcName.startsWith("META-INF/services/") && !svc.isDirectory()) {
                    try (InputStream sis = zip.getInputStream(svc)) {
                        String content = new String(sis.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).toLowerCase();
                        // Suspicious: registering a Java agent or instrumentation service via SPI
                        if (content.contains("java.lang.instrument") || content.contains("instrumentation")) {
                            capabilities.add("!! META-INF/services: Java Instrumentation Agent Service Registration");
                            addReason("META-INF/services registers a Java Instrumentation agent — can rewrite all classes at runtime", reasons);
                            score += 80;
                        }
                        // ClassLoader service provider
                        if (content.contains("classloader") && !content.contains("net.fabricmc") && !content.contains("org.spongepowered")) {
                            capabilities.add("META-INF/services: Custom ClassLoader Service Provider");
                            addReason("META-INF/services declares a custom ClassLoader provider: " + svcName, reasons);
                            score += 30;
                        }
                        // Suspicious: registering RMI or JNDI providers
                        if (content.contains("javax.naming") || content.contains("java.rmi")) {
                            capabilities.add("META-INF/services: RMI / JNDI Provider Registration");
                            addReason("META-INF/services registers JNDI/RMI provider — potential remote code execution vector", reasons);
                            score += 55;
                        }
                    } catch (Exception ignored) {}
                }
            }

            // ── Code Signing Certificate Verification ─────────────────────────
            boolean hasSigFile = false, hasCertFile = false;
            Enumeration<? extends ZipEntry> metaEntries = zip.entries();
            while (metaEntries.hasMoreElements()) {
                ZipEntry me = metaEntries.nextElement();
                String mn = me.getName().toUpperCase();
                if (mn.startsWith("META-INF/") && mn.endsWith(".SF"))  hasSigFile  = true;
                if (mn.startsWith("META-INF/") && (mn.endsWith(".RSA") || mn.endsWith(".DSA") || mn.endsWith(".EC"))) hasCertFile = true;
            }
            // .SF without cert = tampered / stripped signature
            if (hasSigFile && !hasCertFile) {
                capabilities.add("!! Tampered JAR Signature — .SF present but no certificate (.RSA/.DSA)");
                addReason("JAR has signature file but no certificate — signature was stripped or the JAR was modified", reasons);
                score += 70;
            }
            if (hasSigFile && hasCertFile) {
                try (java.util.jar.JarFile jf = new java.util.jar.JarFile(jarFile, true)) {
                    java.util.Enumeration<java.util.jar.JarEntry> jes = jf.entries();
                    boolean verifyFailed = false;
                    outer:
                    while (jes.hasMoreElements()) {
                        java.util.jar.JarEntry je = jes.nextElement();
                        try {
                            jf.getInputStream(je).readAllBytes(); // forces sig check
                            java.security.cert.Certificate[] certs = je.getCertificates();
                            if (certs != null) {
                                for (java.security.cert.Certificate cert : certs) {
                                    if (cert instanceof java.security.cert.X509Certificate x509) {
                                        String certName = x509.getSubjectX500Principal().getName();
                                        // Fabric official CI certificate whitelist
                                        if (certName.contains("CN=Fabric") || certName.contains("O=Fabric") || certName.contains("FabricMC")) {
                                            capabilities.add("Signed by Official Fabric Project (CN=Fabric)");
                                            break outer; // Trusted official certificate
                                        }
                                        if (x509.getIssuerX500Principal().equals(x509.getSubjectX500Principal())) {
                                            capabilities.add("Self-Signed Code Certificate (unverified publisher)");
                                            addReason("Self-signed JAR cert: " + certName, reasons);
                                            score += 25;
                                            break outer;
                                        }
                                    }
                                }
                            }
                        } catch (Exception e2) {
                            if (e2.getMessage() != null && e2.getMessage().toLowerCase().contains("signature")) {
                                verifyFailed = true;
                                break;
                            }
                        }
                    }
                    if (verifyFailed) {
                        capabilities.add("!! JAR Signature Verification FAILED — modified after signing");
                        addReason("Code-signing verification failed — JAR was tampered after it was originally signed", reasons);
                        score += 80;
                    }
                } catch (Exception ignored) {}
            }

            // ── 3. JAR-in-JAR Detection (recursive embedded payload scan) ────

            boolean isFabricApiParent = meta.getModId() != null && meta.getModId().startsWith("fabric-");
            Enumeration<? extends ZipEntry> allEntries = zip.entries();
            while (allEntries.hasMoreElements()) {
                ZipEntry entry = allEntries.nextElement();
                String entryName = entry.getName().toLowerCase();

                boolean isFabricJiJ = entryName.startsWith("meta-inf/jars/fabric-") || entryName.startsWith("META-INF/jars/fabric-");
                boolean isNestedJar = entryName.endsWith(".jar") || entryName.endsWith(".zip");

                if (isNestedJar) {
                    try (InputStream jis = zip.getInputStream(entry)) {
                        byte[] nestedBytes = jis.readAllBytes();
                        // Write to a temp file to scan
                        File tempJar = File.createTempFile("antirat_nested_", ".jar");
                        tempJar.deleteOnExit();
                        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tempJar)) {
                            fos.write(nestedBytes);
                        }
                        // Recursively scan the embedded JAR
                        SecurityReport nestedReport = scanJar(tempJar);
                        
                        // For official Fabric API submodules inside META-INF/jars/, only flag if confirmed malware signatures are found
                        if (isFabricJiJ || isFabricApiParent) {
                            boolean hasRealMalware = false;
                            for (String cap : nestedReport.detectedCapabilities) {
                                if (cap.contains("KNOWN MALWARE") || cap.contains("Discord Webhook") ||
                                    cap.contains("Discord Bot Token") || cap.contains("Telegram Bot Token") ||
                                    cap.contains("SHA-256 MATCHES") || cap.contains("BLOCKED MOD ID") ||
                                    cap.contains("Fractureiser") || cap.contains("WeedHack") ||
                                    cap.contains("SilentNet") || cap.contains("SCREENSHOT EXFILTRATION")) {
                                    hasRealMalware = true;
                                    break;
                                }
                            }
                            if (hasRealMalware) {
                                capabilities.add("!! Malicious Embedded JiJ Module: " + entry.getName());
                                addReason("Nested module contains malware signature: " + entry.getName(), reasons);
                                score += 80;
                            }
                        } else {
                            if (nestedReport.suspicionLevel != SuspicionLevel.CLEAN) {
                                capabilities.add("!! Embedded JAR-in-JAR: " + entry.getName() + " — " + nestedReport.suspicionLevel.label);
                                addReason("Nested JAR detected: " + entry.getName() + " scored " + nestedReport.suspicionScore + "/100 — " + nestedReport.suspicionLevel.label, reasons);
                                score += Math.min(nestedReport.suspicionScore, 90);
                                flaggedStrings.add("[NESTED JAR] " + entry.getName());
                                flaggedStrings.addAll(nestedReport.flaggedStrings);
                            } else {
                                capabilities.add("Embedded JAR/ZIP resource: " + entry.getName() + " (CLEAN 0/100)");
                                // Clean nested library JARs (LWJGL, Kotlin, Fabric) add 0 score penalty
                            }
                        }
                        tempJar.delete();
                    } catch (Exception ignored) {}
                }
            }

            // ── Main class bytecode scan ──────────────────────────────────────
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) continue;
                totalClassCount++;


                try (InputStream is = zip.getInputStream(entry)) {
                    byte[] classBytes = is.readAllBytes();
                    ClassReader reader = new ClassReader(classBytes);
                    ClassNode cn = new ClassNode();
                    reader.accept(cn, ClassReader.SKIP_FRAMES);
                    totalMethodCount += cn.methods.size();

                    // Check class name itself against malware family signatures
                    MalwareRuleEngine.EvalResult classNameEval = MalwareRuleEngine.evaluate("", cn.name);
                    if (classNameEval.scoreAdded > 0) {
                        score += classNameEval.scoreAdded;
                    }
                    for (String family : classNameEval.matchedFamilies) {
                        capabilities.add("KNOWN MALWARE FAMILY (class): " + family);
                        addReason("Class name matches known malware family — " + family + ": " + cn.name, reasons);
                    }

                    // Custom ClassLoader Subclass Bytecode Trap
                    if (cn.superName != null && (cn.superName.equals("java/lang/ClassLoader") ||
                        cn.superName.equals("java/net/URLClassLoader") ||
                        cn.superName.equals("java/security/SecureClassLoader"))) {
                        capabilities.add("Custom ClassLoader Subclass — Dynamic Bytecode Injection Trap");
                        addReason("Class " + cn.name + " extends " + cn.superName + " — potential runtime bytecode injection vector", reasons);
                        score += 65;
                    }

                    // 2. Full De-obfuscation Pipeline
                    Deobfuscator.DeobfuscationReport deobf = Deobfuscator.analyzeClass(cn);

                    // ── Integrate all deobfuscator signals ──────────────────
                    // NOTE: scores below are calibrated to avoid false positives on legitimate mods.
                    // Structural heuristics (I2C, StringBuilder) are very common in clean Java code,
                    // so they only add minor weight — real malware needs C2/process/exfil to score high.
                    if (deobf.hasXorDecryptionLoop)        { score += 12; capabilities.add("XOR Bitwise String Decryption"); }
                    if (deobf.hasArithmeticStringBuilding) { score +=  8; capabilities.add("Arithmetic Delta I2C String Builder (XOR-free obfuscation)"); }
                    if (deobf.hasDesktopOpen)              { score += 80; capabilities.add("Desktop.open() — Runtime.exec Bypass"); }
                    if (deobf.hasEnvPathLookup)            { score += 20; capabilities.add("System.getenv() Sensitive Path Lookup"); }
                    if (deobf.hasDelayedExecution)         { score += 15; capabilities.add("Delayed Execution (Thread.sleep / Timer — scan evasion)"); }
                    if (deobf.hasScriptEngine)             { score += 90; capabilities.add("ScriptEngine / Nashorn JS Arbitrary Code Evaluation"); }
                    if (deobf.hasJndiLookup)               { score += 95; capabilities.add("JNDI InitialContext.lookup() Remote Code Execution"); }
                    if (deobf.hasNativeMethods)            { score += 15; capabilities.add("Native JNI Method Declaration"); }
                    if (deobf.hasSecurityManagerBypass)    { score += 60; capabilities.add("SecurityManager Nullification / Sandbox Bypass"); }
                    if (deobf.hasScreenCapture)            { score += 75; capabilities.add("Robot.createScreenCapture() — Screen Exfiltration"); }
                    if (deobf.hasClipboardAccess)          { score += 65; capabilities.add("Clipboard Access — Crypto Address Hijack Risk"); }
                    if (deobf.hasKeylogger)                { score += 85; capabilities.add("KeyboardFocusManager — Global Keylogger Hook"); }
                    if (deobf.hasDeserializationExploit)   { score += 35; capabilities.add("ObjectInputStream Deserialization Gadget Chain"); }
                    if (deobf.hasAgentInjection)           { score += 90; capabilities.add("VirtualMachine.attach() — Java Agent Injection"); }
                    if (deobf.hasMethodHandles)            { score += 10; capabilities.add("MethodHandles Runtime Method Resolution Bypass"); }
                    if (deobf.hasUnsafeUsage)              { score += 25; capabilities.add("sun.misc.Unsafe Direct Memory / Class Bypass"); }
                    if (deobf.hasStringBuilderObfuscation) { score +=  5; capabilities.add("StringBuilder Char-by-Char Append Obfuscation"); }
                    if (deobf.hasUrlClassLoader)           { score += 45; capabilities.add("URLClassLoader / Remote Class Loading"); }

                    for (String uncovered : deobf.uncoveredStrings) {
                        flagStr(uncovered, flaggedStrings);
                        score += scanForSecrets(uncovered, cn.name + " (deobfuscated)", capabilities, reasons, flaggedStrings);
                    }
                    for (String target : deobf.hiddenReflectionTargets) {
                        capabilities.add("Hidden Reflection Target: " + target);
                        reasons.add("Class.forName target: \"" + target + "\" in " + cn.name);
                        score += 35;
                    }
                    for (String bypass : deobf.detectedBypasses)
                        addReason("[Bypass] " + bypass, reasons);

                    // 3. Bytecode Instruction Visitor
                    boolean isOfficialFrameworkClass = cn.name.startsWith("net/fabricmc/") || cn.name.startsWith("net/minecraft/") || cn.name.startsWith("org/spongepowered/") || cn.name.startsWith("com/mojang/");

                    // Track multi-method "chain" patterns across a class
                    boolean classHasScreenCapture = deobf.hasScreenCapture;
                    boolean classHasImageIOWrite   = false;
                    boolean classHasRobotMove      = false;

                    for (MethodNode mn : cn.methods) {
                        for (AbstractInsnNode insn : mn.instructions) {

                            // ── Method invocations ───────────────────────────
                            if (insn instanceof MethodInsnNode minsn) {
                                String owner = minsn.owner;
                                String mname = minsn.name;

                                // ── Direct process execution ─────────────────
                                if (owner.equals("java/lang/ProcessBuilder") ||
                                    (owner.equals("java/lang/Runtime") && mname.equals("exec")) ||
                                    (owner.equals("java/lang/ProcessHandle") && mname.equals("of"))) {
                                    capabilities.add("Direct Process Execution (ProcessBuilder / Runtime.exec)");
                                    addReason("Invocation of " + owner + "." + mname + " in " + cn.name, reasons);
                                    score += 85;
                                }

                                // ── Minecraft session token access ────────────
                                for (String sm : SESSION_METHODS) {
                                    if (mname.equals(sm)) {
                                        capabilities.add("Minecraft Session Token Access (" + sm + "())");
                                        addReason("Session token method " + sm + "() called in " + cn.name, reasons);
                                        score += 75;
                                    }
                                }

                                // ── HTTP / HTTPS file download method calls ───

                                // URL.openStream() — simplest download pattern
                                if (owner.equals("java/net/URL") && mname.equals("openStream")) {
                                    capabilities.add("HTTP File Download (URL.openStream())");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("URL.openStream() download call in " + cn.name + " — pulls remote content at runtime", reasons);
                                        score += 60;
                                    }
                                }
                                // URL.openConnection() — HttpURLConnection setup
                                if (owner.equals("java/net/URL") && mname.equals("openConnection")) {
                                    capabilities.add("HTTP Connection Setup (URL.openConnection())");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("URL.openConnection() in " + cn.name + " — establishes remote HTTP/HTTPS connection", reasons);
                                        score += 45;
                                    }
                                }
                                // HttpURLConnection.getInputStream() — reading download response
                                if (owner.equals("java/net/HttpURLConnection") && mname.equals("getInputStream")) {
                                    capabilities.add("HTTP Response Body Download (HttpURLConnection.getInputStream())");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("HttpURLConnection.getInputStream() in " + cn.name + " — reads HTTP response body (file download)", reasons);
                                        score += 55;
                                    }
                                }
                                // HttpURLConnection.setRequestMethod — detects POST exfil vs GET download
                                if (owner.equals("java/net/HttpURLConnection") && mname.equals("setRequestMethod")) {
                                    capabilities.add("HTTP Request Method Configuration (possible POST exfiltration)");
                                    score += 20;
                                }
                                // ImageIO.write — image encoding (used in screenshot exfiltration chain)
                                if (owner.equals("javax/imageio/ImageIO") && mname.equals("write")) {
                                    classHasImageIOWrite = true;
                                    capabilities.add("ImageIO.write() — Image File/Stream Encoding");
                                    score += 20;
                                }
                                // Robot.mouseMove / keyPress — mouse/keyboard automation
                                if (owner.equals("java/awt/Robot") && (mname.equals("mouseMove") || mname.equals("mousePress"))) {
                                    classHasRobotMove = true;
                                    capabilities.add("Robot Mouse Automation (Remote Control / Mouse Hijack)");
                                    score += 45;
                                }
                                // Files.copy(InputStream, Path) — writing download to disk
                                if (owner.equals("java/nio/file/Files") && mname.equals("copy")) {
                                    capabilities.add("File Write via Files.copy() — may persist downloaded payload to disk");
                                    addReason("Files.copy() in " + cn.name + " — commonly used to write downloaded JAR/EXE to disk", reasons);
                                    score += 40;
                                }
                                // FileOutputStream / FileWriter — writing bytes to disk (dropper)
                                if ((owner.equals("java/io/FileOutputStream") || owner.equals("java/io/FileWriter") ||
                                     owner.equals("java/io/BufferedOutputStream")) && mname.equals("<init>")) {
                                    capabilities.add("FileOutputStream / FileWriter instantiation — mod writing files to disk");
                                    addReason("File write constructor in " + cn.name + " — may drop payload to disk", reasons);
                                    score += 30;
                                }
                                // FileOutputStream.write(byte[]) — writing a full byte array (binary payload drop)
                                if (owner.equals("java/io/FileOutputStream") && mname.equals("write")) {
                                    capabilities.add("FileOutputStream.write() — writing raw bytes to file (payload drop pattern)");
                                    score += 25;
                                }
                                // Channels.newChannel(url.openStream()) — NIO download pattern
                                if (owner.equals("java/nio/channels/Channels") && mname.equals("newChannel")) {
                                    capabilities.add("NIO Channel Download (Channels.newChannel() — file download via NIO)");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("Channels.newChannel() in " + cn.name + " — NIO-based remote file download pattern", reasons);
                                        score += 50;
                                    }
                                }
                                // Java 11+ HttpClient.send() / sendAsync()
                                if (owner.contains("java/net/http/HttpClient") && (mname.equals("send") || mname.equals("sendAsync"))) {
                                    capabilities.add("Java 11+ HttpClient.send() — modern HTTP file download API");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("HttpClient." + mname + "() in " + cn.name + " — HTTP request sent via modern Java API", reasons);
                                        score += 55;
                                    }
                                }
                                // OkHttp3 — popular HTTP library used in many RATs
                                if (owner.contains("okhttp3") && (mname.equals("execute") || mname.equals("enqueue"))) {
                                    capabilities.add("OkHttp3 HTTP Client — network request library (common in RATs)");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("OkHttp3." + mname + "() in " + cn.name, reasons);
                                        score += 50;
                                    }
                                }
                                // Apache HttpClient
                                if (owner.contains("org/apache/http") && mname.equals("execute")) {
                                    capabilities.add("Apache HttpClient — HTTP request execution");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("Apache HttpClient.execute() in " + cn.name, reasons);
                                        score += 45;
                                    }
                                }
                                // Raw socket connection — custom C2 protocol
                                if (owner.equals("java/net/Socket") && mname.equals("<init>")) {
                                    capabilities.add("Raw TCP Socket Connection (possible C2 channel)");
                                    if (!isOfficialFrameworkClass) {
                                        addReason("new Socket() in " + cn.name + " — raw TCP connection, possible C2 or data exfil channel", reasons);
                                        score += 35;
                                    }
                                }
                                if (owner.equals("javax/net/ssl/SSLSocket") || 
                                    (owner.contains("SSLContext") && mname.equals("createSocket"))) {
                                    capabilities.add("SSL/TLS Socket — encrypted raw channel (C2 evasion)");
                                    if (!isOfficialFrameworkClass) {
                                        score += 35;
                                    }
                                }

                                // ── File I/O on sensitive paths ───────────────
                                if ((owner.equals("java/io/FileInputStream") || owner.equals("java/io/FileReader") ||
                                     owner.equals("java/nio/file/Files")) && mname.contains("read")) {
                                    capabilities.add("File Read Operation (monitor flagged string paths)");
                                }
                            }

                            // ── String constants (LDC) ────────────────────────
                            if (insn instanceof LdcInsnNode ldcInsn && ldcInsn.cst instanceof String str) {
                                String s = str.toLowerCase().trim();

                                // Scan string for secret tokens, webhooks, and bot API keys
                                score += scanForSecrets(str, cn.name, capabilities, reasons, flaggedStrings);

                                // Dynamic JSON rule engine + malware family matching
                                MalwareRuleEngine.EvalResult evalResult = MalwareRuleEngine.evaluate(str, cn.name);
                                if (evalResult.scoreAdded > 0) {
                                    score += evalResult.scoreAdded;
                                    flagStr(str, flaggedStrings);
                                }
                                for (String family : evalResult.matchedFamilies) {
                                    capabilities.add("KNOWN MALWARE FAMILY: " + family);
                                    addReason("Matched known malware family signature — " + family + " in " + cn.name, reasons);
                                }
                                for (String rn : evalResult.matchedRuleNames) {
                                    matchedRules.add(rn);
                                }

                                // Webhook URLs
                                for (String wp : WEBHOOK_PATTERNS) {
                                    if (s.contains(wp)) {
                                        capabilities.add("Discord Webhook Data Exfiltration");
                                        addReason("Hardcoded webhook URL in " + cn.name, reasons);
                                        flagStr(str, flaggedStrings);
                                        score += 80;
                                    }
                                }

                                // Account files
                                for (String af : ACCOUNT_FILES) {
                                    if (s.contains(af)) {
                                        capabilities.add("Minecraft Account / Token File Access");
                                        if (!isOfficialFrameworkClass) {
                                            addReason("Token file reference: \"" + str + "\" in " + cn.name, reasons);
                                            flagStr(str, flaggedStrings);
                                            score += 70;
                                        }
                                    }
                                }

                                // Discord paths
                                for (String dp : DISCORD_PATHS) {
                                    if (s.contains(dp)) {
                                        capabilities.add("Discord Token File Path Access");
                                        addReason("Discord data path: \"" + str + "\" in " + cn.name, reasons);
                                        flagStr(str, flaggedStrings);
                                        score += 75;
                                    }
                                }

                                // Browser credential paths
                                for (String bp : BROWSER_PATHS) {
                                    if (s.contains(bp)) {
                                        capabilities.add("Browser Credential / Cookie File Access");
                                        addReason("Browser data path: \"" + str + "\" in " + cn.name, reasons);
                                        flagStr(str, flaggedStrings);
                                        score += 70;
                                    }
                                }

                                // Crypto wallet paths
                                for (String cp : CRYPTO_PATHS) {
                                    if (s.contains(cp)) {
                                        capabilities.add("Crypto Wallet File Access");
                                        addReason("Wallet path reference: \"" + str + "\" in " + cn.name, reasons);
                                        flagStr(str, flaggedStrings);
                                        score += 70;
                                    }
                                }

                                // Shell command strings
                                for (String ss : SHELL_STRINGS) {
                                    if (s.contains(ss)) {
                                        capabilities.add("Shell / Script Execution String");
                                        addReason("Shell command string: \"" + str + "\" in " + cn.name, reasons);
                                        flagStr(str, flaggedStrings);
                                        score += 55;
                                    }
                                }

                                // ── Persistence mechanism path detection ──────
                                for (String pp : PERSISTENCE_PATHS) {
                                    if (s.contains(pp.toLowerCase())) {
                                        capabilities.add("Persistence Mechanism Path (Startup / Registry / Cron)");
                                        addReason("Persistence path found: \"" + str + "\" in " + cn.name + " — may survive reboot", reasons);
                                        flagStr("[PERSIST] " + str, flaggedStrings);
                                        score += 75;
                                        break;
                                    }
                                }

                                // ── VM / sandbox evasion fingerprinting ──────
                                for (String vm : VM_EVASION_STRINGS) {
                                    if (s.contains(vm.toLowerCase())) {
                                        capabilities.add("VM / Sandbox Evasion — Anti-Analysis Fingerprinting");
                                        addReason("VM/sandbox fingerprint string: \"" + str + "\" in " + cn.name + " — malware uses this to avoid running in analysis environments", reasons);
                                        flagStr("[VM EVADE] " + str, flaggedStrings);
                                        score += 50;
                                        break;
                                    }
                                }

                                // ── Suspicious file write destination paths ───
                                for (String wp : SUSPICIOUS_WRITE_PATHS) {
                                    if (s.contains(wp.toLowerCase())) {
                                        capabilities.add("Suspicious File Write Path (AppData / Temp / System32 / Startup)");
                                        addReason("Suspicious write-target path: \"" + str + "\" in " + cn.name + " — payload may be written to disk", reasons);
                                        flagStr("[WRITE PATH] " + str, flaggedStrings);
                                        score += 60;
                                        break;
                                    }
                                }

                                // ── HTTP/HTTPS URL string detection ──────────
                                if (s.startsWith("http://") || s.startsWith("https://")) {
                                    // Executable / payload file downloads
                                    boolean isExecDownload = s.endsWith(".jar") || s.endsWith(".exe") ||
                                        s.endsWith(".dll") || s.endsWith(".py")  || s.endsWith(".ps1") ||
                                        s.endsWith(".bat") || s.endsWith(".sh")  || s.endsWith(".vbs") ||
                                        s.endsWith(".zip") || s.endsWith(".msi") || s.endsWith(".class");

                                    if (isExecDownload) {
                                        capabilities.add("!! Hardcoded Executable File Download URL");
                                        addReason("Download URL pointing to executable payload: \"" + str + "\" in " + cn.name, reasons);
                                        flagStr("[DOWNLOAD] " + str, flaggedStrings);
                                        score += 85;
                                    }

                                    // Pastebin / raw content services (payload staging)
                                    boolean isPasteSite = s.contains("pastebin.com/raw") || s.contains("pastebin.com/dl") ||
                                        s.contains("raw.githubusercontent.com") || s.contains("gist.github.com") ||
                                        s.contains("paste.ee") || s.contains("hastebin.com") ||
                                        s.contains("rentry.co") || s.contains("ghostbin.com") ||
                                        s.contains("privatebin") || s.contains("justpaste.it");

                                    if (isPasteSite) {
                                        capabilities.add("Paste Site Payload Staging URL (pastebin / gist / rentry)");
                                        addReason("Paste-site URL used for payload staging: \"" + str + "\" in " + cn.name, reasons);
                                        flagStr("[PASTE STAGE] " + str, flaggedStrings);
                                        score += 70;
                                    }

                                    // Telegram Bot API — C2 over Telegram
                                    if (s.contains("api.telegram.org/bot")) {
                                        capabilities.add("!! Telegram Bot API C2 Channel");
                                        addReason("Telegram bot API URL found: \"" + str + "\" — used as C2 channel in " + cn.name, reasons);
                                        flagStr("[TELEGRAM C2] " + str, flaggedStrings);
                                        score += 90;
                                    }

                                    // Raw IP address URLs (no domain = no DNS, harder to block)
                                    if (str.matches("https?://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}.*")) {
                                        capabilities.add("Raw IP Address URL (no DNS — evasion technique)");
                                        addReason("Direct IP URL (no domain name): \"" + str + "\" in " + cn.name, reasons);
                                        flagStr("[RAW IP] " + str, flaggedStrings);
                                        score += 65;
                                    }

                                    // Suspicious TLD download domains (common malware hosting)
                                    if (str.matches("https?://[a-zA-Z0-9._-]+\\.(xyz|top|tk|cf|ga|ml|pw|club|online|fun|site|live|cyou|icu|shop|work)/.*")) {
                                        capabilities.add("Suspicious-TLD Download URL (.xyz/.top/.tk etc.)");
                                        addReason("Suspicious TLD URL: \"" + str + "\" in " + cn.name, reasons);
                                        flagStr("[SUSP URL] " + str, flaggedStrings);
                                        score += 60;
                                    }

                                    // Plain URL — only flag if not a trusted community/project domain
                                    boolean isTrustedUrl = s.contains("modrinth.com") || s.contains("curseforge.com") ||
                                        s.contains("github.com") || s.contains("ko-fi.com") ||
                                        s.contains("patreon.com") || s.contains("caffeinemc.net") ||
                                        s.contains("fabricmc.net") || s.contains("quiltmc.org") ||
                                        s.contains("minecraft.net") || s.contains("mojang.com") ||
                                        s.contains("optifine.net") || s.contains("spongepowered.org") ||
                                        s.contains("liteloader.com") || s.contains("forge") ||
                                        s.contains("discord.gg") || s.contains("discord.com/invite") ||
                                        s.contains("twitter.com") || s.contains("x.com") ||
                                        s.contains("youtube.com") || s.contains("twitch.tv") ||
                                        s.contains("buymeacoffee.com") || s.contains("paypal.com");
                                    if (!isExecDownload && !isPasteSite &&
                                        !s.contains("api.telegram.org") &&
                                        !s.contains("discord.com/api/webhooks") &&
                                        !isTrustedUrl) {
                                        flagStr("[URL] " + str, flaggedStrings);
                                        // Do not add score for plain URLs — they are informational only
                                    }
                                }

                                // High-entropy constant (possible encrypted payload)
                                double entropy = ObfuscationDetector.calculateEntropy(str);
                                if (entropy > 4.8 && str.length() > 30) {
                                    flagStr("[High Entropy] " + (str.length() > 50 ? str.substring(0, 47) + "..." : str), flaggedStrings);
                                    score += 15;
                                }
                            }
                        }
                    }

                    // Per-class attack chain evaluation
                    if (classHasScreenCapture && classHasImageIOWrite) {
                        capabilities.add("!! SCREENSHOT EXFILTRATION CHAIN (Robot.createScreenCapture + ImageIO.write)");
                        addReason("Class " + cn.name + " combines Robot.createScreenCapture() with ImageIO.write() — definitive screen spyware chain", reasons);
                        score += 90;
                    }
                    if (classHasRobotMove) {
                        addReason("Class " + cn.name + " contains mouse automation calls", reasons);
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            reasons.add("Could not fully scan JAR: " + e.getMessage());
        }

        // 4. Stub Mod Detection
        if (totalClassCount <= 3 && totalMethodCount <= 6 && meta.hasEntrypoint()) {
            capabilities.add("Suspicious Near-Empty Stub Mod (possible harmless stub replacement)");
            addReason("Declares Fabric entrypoint(s) with only " + totalClassCount +
                      " class(es) / " + totalMethodCount + " method(s) — classic stub decoy pattern", reasons);
            score += 35;
        }

        for (String ruleName : matchedRules)
            addReason("Matched Dynamic Rule: " + ruleName, reasons);

        // Trust evaluation — massively expanded list of verified open-source mods
        // These mods are all published, open-source, and verified on Modrinth/CurseForge.
        // For trusted mods, only actual C2/stealer/hash signatures override the zero-out.
        String modId = meta.getModId() != null ? meta.getModId().toLowerCase() : "";
        boolean isTrustedMod = modId.startsWith("fabric-") ||
            modId.equals("sodium") || modId.equals("sodium-extra") || modId.equals("reeses-sodium-options") ||
            modId.equals("iris") || modId.equals("lithium") || modId.equals("phosphor") ||
            modId.equals("ferritecore") || modId.equals("immediatelyfast") || modId.equals("modernfix") ||
            modId.equals("chunky") || modId.equals("cloth-config") || modId.equals("cloth_config") ||
            modId.equals("dynamic_fps") || modId.equals("entityculling") || modId.equals("carpet") ||
            modId.equals("entity_model_features") || modId.equals("entity_texture_features") ||
            modId.equals("ixeris") || modId.equals("forgeconfigapiport") || modId.equals("bassaaddon") ||
            modId.equals("modmenu") || modId.equals("mod-menu") ||
            modId.equals("emi") || modId.equals("rei") || modId.equals("jei") ||
            modId.equals("jade") || modId.equals("wthit") || modId.equals("hwyla") ||
            modId.equals("journeymap") || modId.equals("xaeros_minimap") || modId.equals("xaerosworldmap") ||
            modId.equals("appleskin") || modId.equals("inventoryhud") ||
            modId.equals("lambdynamiclights") || modId.equals("lambdabettergrass") ||
            modId.equals("continuity") || modId.equals("enhancedblockentities") || modId.equals("ebe") ||
            modId.equals("indium") || modId.equals("iris-sodium") || modId.equals("canvas") ||
            modId.equals("cull-leaves") || modId.equals("cullleaves") ||
            modId.equals("ok-zoomer") || modId.equals("okzoomer") || modId.equals("zoomify") ||
            modId.equals("replaymod") || modId.equals("litematica") || modId.equals("tweakeroo") ||
            modId.equals("malilib") || modId.equals("minihud") ||
            modId.equals("optsifine") || modId.equals("optifabric") ||
            modId.equals("patchouli") || modId.equals("botania") ||
            modId.equals("trinkets") || modId.equals("origins") ||
            modId.equals("styled-chat") || modId.equals("styledchat") ||
            modId.equals("voxelmap") || modId.equals("voxelmap-updated") ||
            modId.equals("opsec") || modId.equals("lazydfu") || modId.equals("starlight") ||
            modId.equals("krypton") || modId.equals("smoothboot") || modId.equals("raknetify") ||
            modId.equals("c2me") || modId.equals("concurrent-chunk-management-engine") ||
            modId.equals("scalablelux") || modId.equals("sc_scalablelux") ||
            modId.equals("nvidium") || modId.equals("bobby") || modId.equals("distant-horizons") ||
            modId.equals("sodium-shadowy-path-blocks") ||
            capabilities.contains("Signed by Official Fabric Project (CN=Fabric)");

        boolean hasActualMalwareSignature = false;
        for (String cap : capabilities) {
            // ONLY confirmed stealer/C2/injection signatures matter here.
            // Things like URLClassLoader, Desktop.open, KeyboardFocusManager, Thread.sleep
            // are all normal in legitimate Minecraft mods and must NOT be in this list.
            if (cap.contains("KNOWN MALWARE") ||
                cap.contains("Discord Webhook") ||
                cap.contains("Discord Bot Token") ||
                cap.contains("Telegram Bot Token") ||
                cap.contains("Telegram Bot API C2") ||
                cap.contains("SHA-256 MATCHES") ||
                cap.contains("BLOCKED MOD ID") ||
                cap.contains("Fractureiser") ||
                cap.contains("WeedHack") ||
                cap.contains("SilentNet") ||
                cap.contains("EtherHiding") ||
                cap.contains("Raw IP C2 Address") ||
                cap.contains("!! Raw IP") ||
                cap.contains("Paste Site Payload Staging") ||
                cap.contains("Hardcoded Executable File Download") ||
                cap.contains("Malicious Embedded JiJ Module") ||
                cap.contains("JAR Signature Verification FAILED") ||
                cap.contains("Tampered JAR Signature") ||
                cap.contains("MANIFEST: Agent-Class") ||
                cap.contains("META-INF/services: Java Instrumentation")) {
                hasActualMalwareSignature = true;
                break;
            }
        }

        if (isTrustedMod && !hasActualMalwareSignature) {
            score = 0; // Trusted open-source / framework mod — zero malware threat
        }

        SuspicionLevel level;
        if      (score >= 70) level = SuspicionLevel.CRITICAL;
        else if (score >= 40) level = SuspicionLevel.HIGH;
        else if (score >= 25) level = SuspicionLevel.MEDIUM;
        else if (score >= 10) level = SuspicionLevel.LOW;
        else                  level = SuspicionLevel.CLEAN;

        return new SecurityReport(meta, level, score, capabilities, obf, reasons, flaggedStrings);
    }

    private static void flagStr(String s, List<String> list) {
        if (s != null && !s.isEmpty() && !list.contains(s)) list.add(s);
    }

    private static void addReason(String r, List<String> list) {
        if (!list.contains(r)) list.add(r);
    }

    // ── Secret Token & Webhook Scanner ──────────────────────────────────────
    private static int scanForSecrets(String str, String className, Set<String> capabilities, List<String> reasons, List<String> flaggedStrings) {
        if (str == null || str.isEmpty()) return 0;
        int addedScore = 0;

        // Discord Webhook
        if (PAT_DISCORD_WEBHOOK.matcher(str).find()) {
            capabilities.add("!! Hardcoded Discord Webhook URL");
            addReason("Discord Webhook URL found in " + className + ": " + str, reasons);
            flagStr("[DISCORD WEBHOOK] " + str, flaggedStrings);
            addedScore += 85;
        }

        // Discord Bot Token
        if (PAT_DISCORD_BOT_TOKEN.matcher(str).find()) {
            capabilities.add("!! Hardcoded Discord Bot Token");
            addReason("Discord Bot Token found in " + className + ": " + str, reasons);
            flagStr("[DISCORD BOT TOKEN] " + str, flaggedStrings);
            addedScore += 90;
        }

        // Telegram Bot Token
        if (PAT_TELEGRAM_BOT_TOKEN.matcher(str).find()) {
            capabilities.add("!! Hardcoded Telegram Bot Token (C2 / Exfiltration)");
            addReason("Telegram Bot Token found in " + className + ": " + str, reasons);
            flagStr("[TELEGRAM BOT TOKEN] " + str, flaggedStrings);
            addedScore += 90;
        }

        // Slack Webhook / Token
        if (PAT_SLACK_WEBHOOK.matcher(str).find() || PAT_SLACK_TOKEN.matcher(str).find()) {
            capabilities.add("!! Slack Webhook / Bot Token");
            addReason("Slack Webhook / Token found in " + className + ": " + str, reasons);
            flagStr("[SLACK WEBHOOK/TOKEN] " + str, flaggedStrings);
            addedScore += 85;
        }

        // Guilded Webhook / Token
        if (PAT_GUILDED_WEBHOOK.matcher(str).find() || PAT_GUILDED_TOKEN.matcher(str).find()) {
            capabilities.add("!! Guilded Webhook / Bot Token");
            addReason("Guilded Webhook / Token found in " + className + ": " + str, reasons);
            flagStr("[GUILDED WEBHOOK/TOKEN] " + str, flaggedStrings);
            addedScore += 85;
        }

        // Generic Webhook Exfil Service
        if (PAT_GENERIC_WEBHOOK.matcher(str).find()) {
            capabilities.add("!! Generic Webhook Data Exfiltration URL (webhook.site / pipedream)");
            addReason("Generic exfil webhook URL found in " + className + ": " + str, reasons);
            flagStr("[GENERIC WEBHOOK] " + str, flaggedStrings);
            addedScore += 80;
        }

        // GitHub Token
        if (PAT_GITHUB_TOKEN.matcher(str).find()) {
            capabilities.add("!! Hardcoded GitHub Access Token");
            addReason("GitHub PAT found in " + className + ": " + str, reasons);
            flagStr("[GITHUB TOKEN] " + str, flaggedStrings);
            addedScore += 85;
        }

        // AWS Access Key
        if (PAT_AWS_KEY.matcher(str).find()) {
            capabilities.add("!! Hardcoded AWS Access Key");
            addReason("AWS Access Key found in " + className + ": " + str, reasons);
            flagStr("[AWS KEY] " + str, flaggedStrings);
            addedScore += 85;
        }

        return addedScore;
    }
}
