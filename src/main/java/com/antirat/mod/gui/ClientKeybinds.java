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

    private static KeyBinding keyBindingClickGUI;
    private static boolean startupReportShown = false;

    public static void register() {
        // Register Right Shift Keybind for ClickGUI via Fabric API
        keyBindingClickGUI = KeyBindingHelper.registerKeyBinding(new KeyBinding(
            "key.antirat.open_gui",
            InputUtil.Type.KEYSYM,
            GLFW.GLFW_KEY_RIGHT_SHIFT,
            "category.antirat.security"
        ));

        // Client Tick Handler for Keybind and Startup Security Screen
        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            if (client == null) return;

            // Check if startup quarantine report needs to be shown
            if (!startupReportShown && client.currentScreen == null && QuarantineManager.hasQuarantinedMods()) {
                startupReportShown = true;
                List<SecurityScanner.SecurityReport> reports = QuarantineManager.getQuarantinedReports();
                client.execute(() -> client.setScreen(new SecurityReportScreen(reports)));
            }

            // Keybind Trigger
            while (keyBindingClickGUI != null && keyBindingClickGUI.wasPressed()) {
                if (client.currentScreen == null) {
                    client.setScreen(new ClickGUI());
                }
            }
        });
    }
}
