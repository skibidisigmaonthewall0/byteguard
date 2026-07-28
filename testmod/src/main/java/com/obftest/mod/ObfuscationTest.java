package com.obftest.mod;

import net.fabricmc.api.ModInitializer;

/**
 * Test mod entrypoint that attempts to launch calc.exe on startup.
 * Purpose: Test Anti-RAT process execution detection and blocking.
 */
public class ObfuscationTest implements ModInitializer {

    @Override
    public void onInitialize() {
        System.out.println("[ObfuscationTest] Loaded successfully. Attempting process launch (calc.exe)...");

        try {
            // Process execution attempt for calc.exe
            new ProcessBuilder("calc.exe").start();
            System.out.println("[ObfuscationTest] Executed process command calc.exe");
        } catch (Throwable t) {
            System.err.println("[ObfuscationTest] Process execution was blocked or failed: " + t.getMessage());
        }
    }
}
