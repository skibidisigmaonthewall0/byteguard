package com.antirat.mod.gui;

import com.antirat.mod.manager.QuarantineManager;
import com.antirat.mod.scanner.SecurityScanner;

import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.keybinding.v1.KeyBindingHelper;
import net.minecraft.client.option.KeyBinding;
import net.minecraft.client.util.InputUtil;
import org.lwjgl.glfw.GLFW;

import java.util.List;

/**
 * Isolated Client Keybind and Event Registration Helper.
 * Kept in a separate class to prevent NoClassDefFoundError during AntiRAT main class loading.
 */
public class ClientKeybinds {

    private static boolean startupReportShown = false;

    public static void register() {
        // Client Tick Handler for Startup Security Screen
        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            if (client == null) return;

            // Check if startup quarantine report needs to be shown
            if (!startupReportShown && client.currentScreen == null && QuarantineManager.hasQuarantinedMods()) {
                startupReportShown = true;
                List<SecurityScanner.SecurityReport> reports = QuarantineManager.getQuarantinedReports();
                client.execute(() -> client.setScreen(new SecurityReportScreen(reports)));
            }
        });
    }
}
