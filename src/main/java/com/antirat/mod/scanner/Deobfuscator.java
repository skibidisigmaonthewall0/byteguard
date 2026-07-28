package com.antirat.mod.scanner;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Full-Spectrum Bytecode De-obfuscation & Flow Analysis Pipeline.
 *
 * Detects ALL known bypass and obfuscation techniques:
 *  - XOR decryption loops
 *  - Arithmetic delta I2C string building (cumulative int + I2C cast)
 *  - StringBuilder char-by-char append obfuscation
 *  - Base64 encoded string constants
 *  - Char array accumulation (NEWARRAY + char AASTORE)
 *  - Hidden Class.forName / Method.invoke reflection targets
 *  - String split/join reassembly obfuscation
 *  - Desktop.getDesktop().open() exec bypass
 *  - System.getenv() sensitive path variable lookups
 *  - Thread.sleep / Timer / ScheduledExecutor delayed execution
 *  - MethodHandles.lookup().findVirtual() runtime method resolution
 *  - ScriptEngine / Nashorn JS execution
 *  - JNDI InitialContext.lookup() remote code execution
 *  - Native method declaration (JNI)
 *  - SecurityManager nullification
 *  - Robot.createScreenCapture() screen capture
 *  - Clipboard access (getSystemClipboard)
 *  - KeyboardFocusManager keylogger hooks
 *  - ObjectInputStream deserialization exploit
 *  - VirtualMachine.attach() Java agent injection
 *  - Unsafe.defineClass() / Unsafe.allocateMemory() direct memory
 */
public class Deobfuscator {

    private static final String[] SENSITIVE_ENV_VARS = {
        "WINDIR", "SYSTEMROOT", "APPDATA", "LOCALAPPDATA",
        "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "PROGRAMFILES", "PROGRAMDATA", "COMSPEC", "PATH",
        "JAVA_HOME", "USERNAME", "COMPUTERNAME"
    };

    public static class DeobfuscationReport {
        public final List<String> uncoveredStrings    = new ArrayList<>();
        public final List<String> hiddenReflectionTargets = new ArrayList<>();
        public final List<String> detectedBypasses    = new ArrayList<>();
        public boolean hasXorDecryptionLoop        = false;
        public boolean hasArithmeticStringBuilding = false;
        public boolean hasDelayedExecution         = false;
        public boolean hasDesktopOpen              = false;
        public boolean hasEnvPathLookup            = false;
        public boolean hasScriptEngine             = false;
        public boolean hasJndiLookup               = false;
        public boolean hasNativeMethods            = false;
        public boolean hasSecurityManagerBypass    = false;
        public boolean hasScreenCapture            = false;
        public boolean hasClipboardAccess          = false;
        public boolean hasKeylogger                = false;
        public boolean hasDeserializationExploit   = false;
        public boolean hasAgentInjection           = false;
        public boolean hasMethodHandles            = false;
        public boolean hasUnsafeUsage              = false;
        public boolean hasStringBuilderObfuscation = false;
        public boolean hasUrlClassLoader           = false;
    }

    public static DeobfuscationReport analyzeClass(ClassNode cn) {
        DeobfuscationReport report = new DeobfuscationReport();

        // Check for native method declarations (JNI)
        for (MethodNode mn : cn.methods) {
            if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
                report.hasNativeMethods = true;
                addBypass(report, "Native (JNI) method declaration: " + cn.name + "." + mn.name + " — can execute arbitrary native code");
            }
        }

        for (MethodNode mn : cn.methods) {
            analyzeMethod(mn, cn.name, report);
        }

        return report;
    }

    private static void analyzeMethod(MethodNode mn, String className, DeobfuscationReport report) {
        String lastStringLdc = null;

        // Integer simulation stack for arithmetic string reconstruction
        Deque<Integer> intStack = new ArrayDeque<>();
        StringBuilder arithmeticStr = new StringBuilder();
        int i2cCount = 0;

        // StringBuilder append char tracking
        boolean inStringBuilderAppend = false;
        StringBuilder sbObfStr = new StringBuilder();

        // Track consecutive string LDC fragments (split/join reassembly)
        List<String> stringFragments = new ArrayList<>();

        for (AbstractInsnNode insn : mn.instructions) {
            int op = insn.getOpcode();

            // ── Integer push instructions ────────────────────────────────────
            if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) {
                int val = op - Opcodes.ICONST_0; // ICONST_0=3, so val = op-3
                intStack.push(val);
            } else if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) {
                intStack.push(((IntInsnNode) insn).operand);
            } else if (insn instanceof LdcInsnNode ldcInsn) {
                if (ldcInsn.cst instanceof Integer ival) {
                    intStack.push(ival);
                } else if (ldcInsn.cst instanceof String str) {
                    lastStringLdc = str;

                    // Collect string fragments for split/join reassembly
                    if (str.length() >= 1 && str.length() <= 12) {
                        stringFragments.add(str);
                        if (stringFragments.size() >= 3) {
                            String assembled = String.join("", stringFragments);
                            if (assembled.length() >= 5 && isSuspiciousAssembled(assembled)) {
                                addUncovered(report, "[Split/Join Reassembly] " + assembled);
                            }
                        }
                        if (stringFragments.size() > 8) stringFragments.remove(0);
                    } else {
                        stringFragments.clear();
                    }

                    // Base64 decode attempt
                    if (str.length() >= 12 && str.matches("^[A-Za-z0-9+/=]+$")) {
                        tryBase64Decode(str, report);
                    }

                    intStack.clear();
                }
            }

            // ── Arithmetic on int stack ──────────────────────────────────────
            else if (op == Opcodes.IADD) {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a + b); }
            } else if (op == Opcodes.ISUB) {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a - b); }
            } else if (op == Opcodes.IMUL) {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a * b); }
            } else if (op == Opcodes.IAND) {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a & b); }
            } else if (op == Opcodes.IOR)  {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a | b); }
            } else if (op == Opcodes.ISHR) {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a >> b); }
            } else if (op == Opcodes.ISHL) {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a << b); }
            } else if (op == Opcodes.IUSHR) {
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a >>> b); }

            // ── XOR ──────────────────────────────────────────────────────────
            } else if (op == Opcodes.IXOR) {
                report.hasXorDecryptionLoop = true;
                addBypass(report, "XOR (IXOR) bitwise decryption routine in " + className + "." + mn.name);
                if (intStack.size() >= 2) { int b = intStack.pop(), a = intStack.pop(); intStack.push(a ^ b); }

            // ── I2C — arithmetic delta char building ─────────────────────────
            } else if (op == Opcodes.I2C) {
                report.hasArithmeticStringBuilding = true;
                addBypass(report, "Arithmetic delta char-by-char string building (I2C) in " + className);
                if (!intStack.isEmpty()) {
                    int charVal = intStack.pop() & 0xFFFF;
                    char c = (char) charVal;
                    if (c >= 32 && c < 127) {
                        arithmeticStr.append(c);
                        i2cCount++;
                        if (i2cCount >= 3) {
                            addUncovered(report, "[Arithmetic Build] " + arithmeticStr);
                        }
                    } else {
                        arithmeticStr.setLength(0);
                        i2cCount = 0;
                    }
                }
            }

            // ── Method call analysis ─────────────────────────────────────────
            if (insn instanceof MethodInsnNode minsn) {
                String owner = minsn.owner;
                String name  = minsn.name;
                String desc  = minsn.desc;

                // ── Reflection ──────────────────────────────────────────────
                if (owner.equals("java/lang/Class") && name.equals("forName")) {
                    if (lastStringLdc != null) {
                        if (!report.hiddenReflectionTargets.contains(lastStringLdc))
                            report.hiddenReflectionTargets.add(lastStringLdc);
                    }
                    addBypass(report, "Class.forName() dynamic class loading in " + className);
                }
                if (owner.equals("java/lang/reflect/Method") && name.equals("invoke")) {
                    addBypass(report, "Method.invoke() reflective invocation in " + className);
                }
                if (owner.equals("java/lang/Class") && (name.equals("getMethod") || name.equals("getDeclaredMethod"))) {
                    addBypass(report, "Class.getMethod(\"" + (lastStringLdc != null ? lastStringLdc : "?") + "\") reflective method lookup in " + className);
                }

                // ── MethodHandles ───────────────────────────────────────────
                if (owner.contains("MethodHandles") || owner.contains("MethodHandle")) {
                    report.hasMethodHandles = true;
                    addBypass(report, "MethodHandles.lookup().findVirtual() runtime method resolution in " + className + " — bypasses reflection checks");
                }

                // ── Desktop open/browse/exec ─────────────────────────────────
                if (owner.equals("java/awt/Desktop") && (name.equals("open") || name.equals("browse") || name.equals("exec") || name.equals("mail"))) {
                    report.hasDesktopOpen = true;
                    addBypass(report, "Desktop.getDesktop()." + name + "() — alternative to Runtime.exec in " + className);
                }

                // ── System.getenv sensitive path vars ────────────────────────
                if (owner.equals("java/lang/System") && name.equals("getenv") && lastStringLdc != null) {
                    String envUpper = lastStringLdc.toUpperCase();
                    for (String se : SENSITIVE_ENV_VARS) {
                        if (envUpper.equals(se)) {
                            report.hasEnvPathLookup = true;
                            addBypass(report, "System.getenv(\"" + lastStringLdc + "\") path-building bypass in " + className);
                            addUncovered(report, "[EnvPath] System.getenv(\"" + lastStringLdc + "\")");
                            break;
                        }
                    }
                }

                // ── ScriptEngine / Nashorn / Graal JS execution ──────────────
                if (owner.contains("ScriptEngine") || owner.contains("ScriptEngineManager") ||
                    owner.contains("NashornScriptEngine") || owner.contains("Invocable")) {
                    report.hasScriptEngine = true;
                    addBypass(report, "ScriptEngine/Nashorn JS execution in " + className + " — can eval arbitrary code strings");
                }

                // ── JNDI remote code execution ───────────────────────────────
                if ((owner.contains("InitialContext") || owner.contains("NamingContext")) && name.equals("lookup")) {
                    report.hasJndiLookup = true;
                    addBypass(report, "JNDI InitialContext.lookup() in " + className + " — remote class execution (Log4Shell-style)");
                }

                // ── Delayed execution ─────────────────────────────────────────
                if ((owner.equals("java/lang/Thread") && name.equals("sleep")) ||
                    (owner.equals("java/util/Timer") && name.equals("schedule")) ||
                    (owner.contains("ScheduledExecutor") && (name.equals("schedule") || name.equals("scheduleAtFixedRate"))) ||
                    (owner.contains("CompletableFuture") && name.equals("runAsync"))) {
                    report.hasDelayedExecution = true;
                    addBypass(report, "Delayed execution (" + owner.replace("java/util/", "") + "." + name + ") in " + className + " — may fire after pre-launch scan");
                }

                // ── Screen capture / Robot ────────────────────────────────────
                if (owner.equals("java/awt/Robot") && (name.equals("createScreenCapture") || name.equals("getPixelColor"))) {
                    report.hasScreenCapture = true;
                    addBypass(report, "Robot.createScreenCapture() in " + className + " — can exfiltrate screen content (e.g. session tokens displayed on screen)");
                }

                // ── Clipboard ─────────────────────────────────────────────────
                if ((owner.contains("Clipboard") || owner.contains("Toolkit")) &&
                    (name.equals("getSystemClipboard") || name.equals("getContents") || name.equals("setContents"))) {
                    report.hasClipboardAccess = true;
                    addBypass(report, "Clipboard access (" + name + ") in " + className + " — can steal or replace clipboard content (crypto address swap)");
                }

                // ── Keylogger via KeyboardFocusManager ───────────────────────
                if ((owner.contains("KeyboardFocusManager") || owner.contains("KeyEventDispatcher")) &&
                    (name.equals("addKeyEventDispatcher") || name.equals("addKeyEventPostProcessor"))) {
                    report.hasKeylogger = true;
                    addBypass(report, "KeyboardFocusManager keylogger hook in " + className + " — intercepts all key events globally");
                }

                // ── Deserialization exploit ──────────────────────────────────
                if (owner.equals("java/io/ObjectInputStream") && name.equals("readObject")) {
                    report.hasDeserializationExploit = true;
                    addBypass(report, "ObjectInputStream.readObject() deserialization in " + className + " — can trigger gadget chain exploits");
                }

                // ── Java Agent injection via Attach API ──────────────────────
                if (owner.contains("VirtualMachine") && (name.equals("attach") || name.equals("loadAgent") || name.equals("loadAgentLibrary"))) {
                    report.hasAgentInjection = true;
                    addBypass(report, "VirtualMachine." + name + "() agent injection in " + className + " — can inject Java agents into running JVMs");
                }

                // ── sun.misc.Unsafe / jdk.internal.misc.Unsafe ───────────────
                if ((owner.contains("sun/misc/Unsafe") || owner.contains("jdk/internal/misc/Unsafe")) &&
                    (name.equals("defineClass") || name.equals("allocateMemory") || name.equals("putAddress") || name.equals("defineAnonymousClass"))) {
                    report.hasUnsafeUsage = true;
                    addBypass(report, "Unsafe." + name + "() in " + className + " — bypasses JVM memory/class safety");
                }

                // ── SecurityManager nullification ─────────────────────────────
                if (owner.equals("java/lang/System") && name.equals("setSecurityManager")) {
                    report.hasSecurityManagerBypass = true;
                    addBypass(report, "System.setSecurityManager(null) in " + className + " — disables all security sandbox checks");
                }

                // ── URLClassLoader remote class loading ───────────────────────
                if (owner.contains("URLClassLoader") || (owner.contains("ClassLoader") && name.equals("loadClass"))) {
                    report.hasUrlClassLoader = true;
                    addBypass(report, "URLClassLoader / ClassLoader.loadClass() in " + className + " — can load classes from remote URL or byte array");
                }

                // ── StringBuilder char-by-char append obfuscation ────────────
                if (owner.equals("java/lang/StringBuilder") && name.equals("append") && desc.equals("(C)Ljava/lang/StringBuilder;")) {
                    report.hasStringBuilderObfuscation = true;
                    if (!intStack.isEmpty()) {
                        int charVal = intStack.peek() & 0xFFFF;
                        char c = (char) charVal;
                        if (c >= 32 && c < 127) {
                            sbObfStr.append(c);
                            if (sbObfStr.length() >= 3) {
                                addUncovered(report, "[StringBuilder Char Build] " + sbObfStr);
                            }
                        }
                    }
                } else if (owner.equals("java/lang/StringBuilder") && name.equals("toString") && sbObfStr.length() > 0) {
                    addUncovered(report, "[StringBuilder Complete] " + sbObfStr);
                    sbObfStr.setLength(0);
                }
            }
        }

        // Flush any remaining reconstructed arithmetic string
        if (arithmeticStr.length() >= 3) {
            addUncovered(report, "[Arithmetic Build Complete] " + arithmeticStr);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void addBypass(DeobfuscationReport report, String msg) {
        if (!report.detectedBypasses.contains(msg)) report.detectedBypasses.add(msg);
    }

    private static void addUncovered(DeobfuscationReport report, String msg) {
        if (!report.uncoveredStrings.contains(msg)) report.uncoveredStrings.add(msg);
    }

    private static void tryBase64Decode(String str, DeobfuscationReport report) {
        try {
            byte[] decoded = Base64.getDecoder().decode(str);
            String decodedStr = new String(decoded, StandardCharsets.UTF_8);
            if (isPrintableAscii(decodedStr)) {
                addUncovered(report, "[Base64] " + decodedStr);
            }
        } catch (Exception ignored) {}
    }

    private static boolean isSuspiciousAssembled(String s) {
        String sl = s.toLowerCase();
        return sl.contains("powershell") || sl.contains("calc") || sl.contains("cmd") ||
               sl.contains("exec") || sl.contains("discord") || sl.contains("webhook") ||
               sl.contains("appdata") || sl.contains("launcher") || sl.contains("token") ||
               sl.contains("http") || sl.contains("socket") || sl.contains("runtime");
    }

    private static boolean isPrintableAscii(String str) {
        if (str == null || str.isEmpty()) return false;
        long printable = str.chars().filter(c -> c >= 32 && c <= 126).count();
        return (double) printable / str.length() >= 0.80;
    }
}
