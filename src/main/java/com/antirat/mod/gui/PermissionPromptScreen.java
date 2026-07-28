package com.antirat.mod.gui;

import com.antirat.mod.manager.PermissionManager;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.text.Text;

import java.util.function.Consumer;

/**
 * Interactive runtime permission prompt modal screen.
 * Uses 1.21 robust DrawContext.drawText API to avoid NoSuchMethodError.
 */
public class PermissionPromptScreen extends Screen {

    private final String modName;
    private final String operationType;
    private final String targetPath;
    private final Consumer<Boolean> callback;
    private boolean rememberChoice = true;

    public PermissionPromptScreen(String modName, String operationType, String targetPath, Consumer<Boolean> callback) {
        super(Text.literal("Anti-RAT Security Permission Request"));
        this.modName = modName;
        this.operationType = operationType;
        this.targetPath = targetPath;
        this.callback = callback;
    }

    @Override
    protected void init() {
        int midX = this.width / 2;
        int midY = this.height / 2;

        // Allow Button
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Allow"), button -> {
            if (rememberChoice) {
                PermissionManager.rememberDecision(modName, operationType, targetPath, true);
            }
            callback.accept(true);
            close();
        }).dimensions(midX - 110, midY + 45, 100, 20).build());

        // Deny Button
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Deny"), button -> {
            if (rememberChoice) {
                PermissionManager.rememberDecision(modName, operationType, targetPath, false);
            }
            callback.accept(false);
            close();
        }).dimensions(midX + 10, midY + 45, 100, 20).build());

        // Toggle Remember Choice
        this.addDrawableChild(ButtonWidget.builder(Text.literal("Remember Choice: " + (rememberChoice ? "YES" : "NO")), button -> {
            rememberChoice = !rememberChoice;
            button.setMessage(Text.literal("Remember Choice: " + (rememberChoice ? "YES" : "NO")));
        }).dimensions(midX - 90, midY + 70, 180, 18).build());
    }

    private void drawText(DrawContext context, String text, int x, int y, int color) {
        context.drawText(this.textRenderer, Text.literal(text), x, y, color, true);
    }

    private void drawCenteredText(DrawContext context, String text, int centerX, int y, int color) {
        int width = this.textRenderer.getWidth(text);
        context.drawText(this.textRenderer, Text.literal(text), centerX - width / 2, y, color, true);
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        context.fill(0, 0, this.width, this.height, 0xFA121212);

        int midX = this.width / 2;
        int midY = this.height / 2;

        int boxLeft = midX - 180;
        int boxTop = midY - 90;
        int boxWidth = 360;
        int boxHeight = 190;

        // Dark modal popup background
        context.fill(boxLeft, boxTop, boxLeft + boxWidth, boxTop + boxHeight, 0xF0181818);

        drawCenteredText(context, "SECURITY PERMISSION PROMPT", midX, boxTop + 12, 0xFF5555);

        int y = boxTop + 35;
        drawText(context, "Mod Name: ", boxLeft + 20, y, 0xAAAAAA);
        drawText(context, modName, boxLeft + 100, y, 0xFFFFFF);

        y += 18;
        drawText(context, "Operation: ", boxLeft + 20, y, 0xAAAAAA);
        drawText(context, operationType, boxLeft + 100, y, 0xFFFF55);

        y += 18;
        drawText(context, "Target: ", boxLeft + 20, y, 0xAAAAAA);
        y += 14;
        String truncatedPath = targetPath.length() > 45 ? "..." + targetPath.substring(targetPath.length() - 42) : targetPath;
        drawText(context, truncatedPath, boxLeft + 20, y, 0x00FFCC);

        super.render(context, mouseX, mouseY, delta);
    }

    @Override
    public boolean shouldCloseOnEsc() {
        return false;
    }
}
