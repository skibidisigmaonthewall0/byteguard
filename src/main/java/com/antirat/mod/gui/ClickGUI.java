package com.antirat.mod.gui;

import com.antirat.mod.config.SettingsStorage;
import com.antirat.mod.manager.PermissionManager;
import com.antirat.mod.manager.QuarantineManager;
import com.antirat.mod.scanner.SecurityScanner;
import com.antirat.mod.util.Logger;

import net.minecraft.client.font.TextRenderer;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.client.gui.widget.TextFieldWidget;
import net.minecraft.text.Text;

import java.lang.reflect.Method;
import java.util.List;

/**
 * Main Modern ClickGUI screen for configuration, Whitelist/Blacklist management,
 * Log Viewer, Scan Results, and JSON Import/Export.
 */
public class ClickGUI extends Screen {

    public enum Tab {
        SETTINGS,
        WHITELIST,
        BLACKLIST,
        SCAN_RESULTS,
        LOGS,
        IMPORT_EXPORT
    }

    private Tab currentTab = Tab.SETTINGS;
    private TextFieldWidget searchBox;
    private TextFieldWidget jsonBox;

    public ClickGUI() {
        super(Text.literal("Anti-RAT Security Control Panel"));
    }

    @Override
    protected void init() {
        int midX = this.width / 2;
        int topY = 30;

        // Navigation Tabs
        int tabWidth = 70;
        int startX = midX - (tabWidth * 6) / 2;

        for (int i = 0; i < Tab.values().length; i++) {
            Tab tab = Tab.values()[i];
            this.addDrawableChild(ButtonWidget.builder(Text.literal(tab.name()), button -> {
                currentTab = tab;
                rebuildGUI();
            }).dimensions(startX + (i * tabWidth), topY, tabWidth - 2, 20).build());
        }

        // Search Filter Box
        searchBox = new TextFieldWidget(this.textRenderer, midX - 150, topY + 26, 300, 18, Text.literal("Search..."));
        searchBox.setPlaceholder(Text.literal("Search mods or logs..."));
        this.addDrawableChild(searchBox);

        buildTabContent();
    }

    private void rebuildGUI() {
        this.clearChildren();
        this.init();
    }

    private void buildTabContent() {
        int midX = this.width / 2;
        int contentY = 85;

        if (currentTab == Tab.SETTINGS) {
            // Safe Mode Toggle
            this.addDrawableChild(ButtonWidget.builder(
                Text.literal("Safe Mode: " + (PermissionManager.isSafeMode() ? "ENABLED" : "DISABLED")),
                button -> {
                    PermissionManager.setSafeMode(!PermissionManager.isSafeMode());
                    button.setMessage(Text.literal("Safe Mode: " + (PermissionManager.isSafeMode() ? "ENABLED" : "DISABLED")));
                }
            ).dimensions(midX - 120, contentY, 240, 20).build());

            // Emergency Kill Switch Toggle
            this.addDrawableChild(ButtonWidget.builder(
                Text.literal("Emergency Kill Switch: " + (PermissionManager.isKillSwitchActive() ? "ACTIVE (ALL BLOCKED)" : "OFF")),
                button -> {
                    PermissionManager.setKillSwitch(!PermissionManager.isKillSwitchActive());
                    button.setMessage(Text.literal("Emergency Kill Switch: " + (PermissionManager.isKillSwitchActive() ? "ACTIVE (ALL BLOCKED)" : "OFF")));
                }
            ).dimensions(midX - 140, contentY + 26, 280, 20).build());

            // Global Default Mod Behavior Toggle
            this.addDrawableChild(ButtonWidget.builder(
                Text.literal("Default Behavior: " + SettingsStorage.getData().defaultModBehavior),
                button -> {
                    String current = SettingsStorage.getData().defaultModBehavior;
                    String next = "ASK".equals(current) ? "ALWAYS_ALLOW" : ("ALWAYS_ALLOW".equals(current) ? "ALWAYS_DENY" : "ASK");
                    SettingsStorage.getData().defaultModBehavior = next;
                    SettingsStorage.save();
                    button.setMessage(Text.literal("Default Behavior: " + next));
                }
            ).dimensions(midX - 120, contentY + 52, 240, 20).build());

        } else if (currentTab == Tab.IMPORT_EXPORT) {
            jsonBox = new TextFieldWidget(this.textRenderer, midX - 180, contentY, 360, 60, Text.literal("JSON Data"));
            jsonBox.setMaxLength(10000);
            jsonBox.setText(SettingsStorage.exportJson());
            this.addDrawableChild(jsonBox);

            this.addDrawableChild(ButtonWidget.builder(Text.literal("Import JSON"), button -> {
                if (jsonBox != null && SettingsStorage.importJson(jsonBox.getText())) {
                    Logger.log("SYSTEM", "CONFIG", "Successfully imported JSON permissions", "SUCCESS");
                }
            }).dimensions(midX - 100, contentY + 70, 95, 20).build());

            this.addDrawableChild(ButtonWidget.builder(Text.literal("Export JSON"), button -> {
                if (jsonBox != null) {
                    jsonBox.setText(SettingsStorage.exportJson());
                }
            }).dimensions(midX + 5, contentY + 70, 95, 20).build());
        }
    }

    private static void safeDrawText(DrawContext context, TextRenderer textRenderer, String text, int x, int y, int color) {
        try {
            context.drawText(textRenderer, Text.literal(text), x, y, color, true);
        } catch (Throwable t1) {
            try {
                for (Method m : context.getClass().getMethods()) {
                    if (m.getName().equals("drawText") || m.getName().contains("51439")) {
                        if (m.getParameterCount() == 6) {
                            Object textArg = m.getParameterTypes()[1] == String.class ? text : Text.literal(text);
                            m.invoke(context, textRenderer, textArg, x, y, color, true);
                            return;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private void drawText(DrawContext context, String text, int x, int y, int color) {
        safeDrawText(context, this.textRenderer, text, x, y, color);
    }

    private void drawCenteredText(DrawContext context, String text, int centerX, int y, int color) {
        int width = this.textRenderer.getWidth(text);
        safeDrawText(context, this.textRenderer, text, centerX - width / 2, y, color);
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        context.fill(0, 0, this.width, this.height, 0xFA121212);

        int midX = this.width / 2;
        drawCenteredText(context, "ANTI-RAT SECURITY DASHBOARD", midX, 10, 0x00FFCC);

        int contentY = 85;
        String query = searchBox != null ? searchBox.getText().toLowerCase() : "";

        if (currentTab == Tab.WHITELIST) {
            drawCenteredText(context, "Whitelisted Mods", midX, contentY, 0x55FF55);
            int y = contentY + 18;
            for (String modId : SettingsStorage.getData().whitelistMods) {
                if (!query.isEmpty() && !modId.toLowerCase().contains(query)) continue;
                drawCenteredText(context, "• " + modId, midX, y, 0xFFFFFF);
                y += 14;
            }
        } else if (currentTab == Tab.BLACKLIST) {
            drawCenteredText(context, "Blacklisted Mods", midX, contentY, 0xFF5555);
            int y = contentY + 18;
            for (String modId : SettingsStorage.getData().blacklistMods) {
                if (!query.isEmpty() && !modId.toLowerCase().contains(query)) continue;
                drawCenteredText(context, "• " + modId, midX, y, 0xFFFFFF);
                y += 14;
            }
        } else if (currentTab == Tab.LOGS) {
            drawCenteredText(context, "Live Action Logs", midX, contentY, 0xFFFF55);
            int y = contentY + 18;
            List<String> logs = Logger.getRecentLogs();
            int count = 0;
            for (int i = logs.size() - 1; i >= 0 && count < 10; i--) {
                String log = logs.get(i);
                if (!query.isEmpty() && !log.toLowerCase().contains(query)) continue;
                drawCenteredText(context, log, midX, y, log.contains("DENIED") ? 0xFF5555 : 0xAAAAAA);
                y += 12;
                count++;
            }
        } else if (currentTab == Tab.SCAN_RESULTS) {
            drawCenteredText(context, "Pre-Launch Scan Quarantine Reports", midX, contentY, 0xFF8800);
            int y = contentY + 18;
            List<SecurityScanner.SecurityReport> reports = QuarantineManager.getQuarantinedReports();
            if (reports.isEmpty()) {
                drawCenteredText(context, "No quarantined mods found during startup.", midX, y, 0x888888);
            } else {
                for (SecurityScanner.SecurityReport rep : reports) {
                    if (!query.isEmpty() && !rep.metadata.getName().toLowerCase().contains(query)) continue;
                    drawCenteredText(context, rep.metadata.getName() + " | Level: " + rep.suspicionLevel.label + " | Obf Score: " + rep.obfuscationResult.score, midX, y, rep.suspicionLevel.colorHex);
                    y += 14;
                }
            }
        }

        super.render(context, mouseX, mouseY, delta);
    }
}
