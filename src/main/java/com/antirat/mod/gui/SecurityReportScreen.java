package com.antirat.mod.gui;

import com.antirat.mod.manager.PermissionManager;
import com.antirat.mod.manager.QuarantineManager;
import com.antirat.mod.scanner.SecurityScanner;

import net.minecraft.client.MinecraftClient;
import net.minecraft.client.font.TextRenderer;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.text.Text;
import net.minecraft.util.Util;

import java.lang.reflect.Method;
import java.util.List;

/**
 * Pre-launch security scan report screen.
 * Robust reflection text drawing fallback to prevent NoSuchMethodError on 1.21 Intermediary mappings.
 */
public class SecurityReportScreen extends Screen {

    private final List<SecurityScanner.SecurityReport> reports;
    private int currentIndex = 0;

    public SecurityReportScreen(List<SecurityScanner.SecurityReport> reports) {
        super(Text.literal("Anti-RAT Security Scan Report"));
        this.reports = reports;
    }

    @Override
    protected void init() {
        if (reports == null || reports.isEmpty()) {
            close();
            return;
        }

        SecurityScanner.SecurityReport current = reports.get(currentIndex);
        int midX = this.width / 2;
        int bottomY = this.height - 40;

        // Allow Once
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Allow Once"), button -> {
            advanceOrClose();
        }).dimensions(midX - 180, bottomY, 80, 20).build());

        // Always Allow
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Always Allow"), button -> {
            PermissionManager.addToWhitelist(current.metadata.getModId());
            advanceOrClose();
        }).dimensions(midX - 95, bottomY, 90, 20).build());

        // Quarantine
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Quarantine"), button -> {
            QuarantineManager.moveJarToQuarantine(current.metadata.getJarFile());
            advanceOrClose();
        }).dimensions(midX, bottomY, 85, 20).build());

        // Open Folder
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Open Folder"), button -> {
            if (current.metadata.getJarFile() != null) {
                Util.getOperatingSystem().open(current.metadata.getJarFile().getParentFile());
            }
        }).dimensions(midX + 90, bottomY, 85, 20).build());

        // Close Minecraft (Protection Stop)
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Close Minecraft"), button -> {
            MinecraftClient.getInstance().scheduleStop();
        }).dimensions(midX - 60, bottomY + 24, 120, 16).build());
    }

    private void advanceOrClose() {
        currentIndex++;
        if (currentIndex < reports.size()) {
            this.clearChildren();
            this.init();
        } else {
            close();
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

        int startY = 20;
        int midX = this.width / 2;

        drawCenteredText(context, "Anti-RAT Pre-Launch Security Warning", midX, startY, 0xFF5555);

        if (reports != null && !reports.isEmpty() && currentIndex < reports.size()) {
            SecurityScanner.SecurityReport current = reports.get(currentIndex);

            drawCenteredText(context, "Scanned Mod (" + (currentIndex + 1) + "/" + reports.size() + ")", midX, startY + 14, 0xAAAAAA);

            // Warning Box Header
            int boxTop = startY + 32;
            int boxLeft = midX - 220;
            int boxWidth = 440;

            context.fill(boxLeft, boxTop, boxLeft + boxWidth, boxTop + 140, 0xCC111111);

            int y = boxTop + 8;
            drawText(context, "Mod Name: " + current.metadata.getName(), boxLeft + 12, y, 0xFFFFFF);
            y += 12;
            drawText(context, "JAR File: " + (current.metadata.getJarFile() != null ? current.metadata.getJarFile().getName() : "Unknown"), boxLeft + 12, y, 0xCCCCCC);
            y += 12;
            drawText(context, "Suspicion Level: " + current.suspicionLevel.label + " (Score: " + current.suspicionScore + "/100)", boxLeft + 12, y, current.suspicionLevel.colorHex);
            y += 12;
            drawText(context, "Obfuscation Score: " + current.obfuscationResult.score + "/100", boxLeft + 12, y, 0xFFAA00);
            y += 14;

            drawText(context, "Detected Capabilities:", boxLeft + 12, y, 0xFFFF55);
            y += 12;
            if (current.detectedCapabilities.isEmpty()) {
                drawText(context, "  - None detected", boxLeft + 20, y, 0x888888);
                y += 12;
            } else {
                for (String cap : current.detectedCapabilities) {
                    drawText(context, "  - " + cap, boxLeft + 20, y, 0xFF8888);
                    y += 12;
                }
            }

            y += 6;
            drawText(context, "Flag Reasons:", boxLeft + 12, y, 0xFFFF55);
            y += 12;
            for (int i = 0; i < Math.min(3, current.flaggedReasons.size()); i++) {
                drawText(context, "  - " + current.flaggedReasons.get(i), boxLeft + 20, y, 0xDDDDDD);
                y += 12;
            }

            // Warning Text Box at bottom
            int warningY = boxTop + 150;
            drawCenteredText(context, "Dangerous mod detected and quarantined.", midX, warningY, 0xFF3333);
            drawCenteredText(context, "Minecraft has been paused to protect your files and account data.", midX, warningY + 12, 0xEEEEEE);
            drawCenteredText(context, "This mod appears malicious or heavily obfuscated. Please review carefully.", midX, warningY + 24, 0xAAAAAA);
        }

        super.render(context, mouseX, mouseY, delta);
    }

    @Override
    public boolean shouldCloseOnEsc() {
        return false;
    }
}
