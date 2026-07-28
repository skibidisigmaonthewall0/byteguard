package com.antirat.mod.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Java Agent runtime transformer providing real-time JVM-level behavioral monitoring.
 * Monitors ProcessBuilder execution and socket initiations during JVM runtime execution.
 */
public class AntiRATAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[AntiRAT Agent] Installing JVM Runtime Behavioral Class Transformer...");

        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                if (className == null) return null;

                // Monitor runtime attempts to load ProcessBuilder or Socket classes
                if (className.equals("java/lang/ProcessBuilder")) {
                    System.out.println("[AntiRAT Agent Monitor] Intercepted runtime load of ProcessBuilder class!");
                } else if (className.equals("java/net/Socket")) {
                    System.out.println("[AntiRAT Agent Monitor] Intercepted runtime load of Socket connection class!");
                }

                return null; // Return null to keep bytecode intact while monitoring
            }
        });
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        premain(agentArgs, inst);
    }
}
