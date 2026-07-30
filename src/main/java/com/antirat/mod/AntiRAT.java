package com.antirat.mod;

import com.antirat.mod.config.SettingsStorage;
import com.antirat.mod.gui.ClientKeybinds;
import com.antirat.mod.gui.NativeSecurityWindow;
import com.antirat.mod.manager.QuarantineManager;
import com.antirat.mod.scanner.MalwareRuleEngine;
import com.antirat.mod.scanner.SecurityScanner;
import com.antirat.mod.util.Logger;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Main Anti-RAT entrypoint implementing PreLaunchEntrypoint, ModInitializer, and ClientModInitializer.
 * Synchronously halts pre-launch loading, evaluates dynamic JSON rules, and displays native security window.
 */
public class AntiRAT implements PreLaunchEntrypoint, ModInitializer, ClientModInitializer {

    public static final String MOD_ID = "antirat";

    @Override
    public void onPreLaunch() {
        System.out.println("[AntiRAT] Running Pre-Launch Security Scanning Gate...");
        try {
            File gameDir = FabricLoader.getInstance().getGameDir().toFile();
            Logger.init(gameDir);
            QuarantineManager.init(gameDir);
            SettingsStorage.init(new File(gameDir, "config"));
            MalwareRuleEngine.init(gameDir);

            List<SecurityScanner.SecurityReport> flaggedReports = new ArrayList<>();

            File modsDir = new File(gameDir, "mods");
            if (modsDir.exists() && modsDir.isDirectory()) {
                File[] files = modsDir.listFiles((dir, name) -> name.endsWith(".jar"));
                if (files != null) {
                    for (File jar : files) {
                        String name = jar.getName().toLowerCase();
                        if (name.contains("anti-rat") || name.contains("antirat")) {
                            continue;
                        }
                        SecurityScanner.SecurityReport report = SecurityScanner.scanJar(jar);
                        System.out.println(String.format("[AntiRAT Scan] Jar: %s | Suspicion: %s (Score: %d) | Obf Score: %d",
                            jar.getName(), report.suspicionLevel.label, report.suspicionScore, report.obfuscationResult.score));

                        if (report.suspicionLevel != SecurityScanner.SuspicionLevel.CLEAN || report.suspicionScore > 25) {
                            QuarantineManager.addQuarantinedReport(report);
                            flaggedReports.add(report);
                        }
                    }
                }
            }

            System.out.println("[AntiRAT] Pre-Launch Scan completed. Quarantined mods count: " + flaggedReports.size());

            // Synchronously launch Native Security Gate Window and PAUSE game boot thread if suspicious mods exist!
            if (!flaggedReports.isEmpty()) {
                NativeSecurityWindow.showPreLaunchWindow(flaggedReports);
            }

        } catch (Throwable t) {
            System.err.println("[AntiRAT Error] Exception during pre-launch scan: " + t.getMessage());
            t.printStackTrace();
        }
    }

    @Override
    public void onInitialize() {
        System.out.println("[AntiRAT] Initializing Anti-RAT Core Engine...");
    }

    @Override
    public void onInitializeClient() {
        System.out.println("[AntiRAT] Initializing Client Hooks...");
        try {
            ClientKeybinds.register();
        } catch (Throwable t) {
            System.err.println("[AntiRAT Warning] Fabric API client keybind module unavailable: " + t.getMessage());
        }
    }
}
