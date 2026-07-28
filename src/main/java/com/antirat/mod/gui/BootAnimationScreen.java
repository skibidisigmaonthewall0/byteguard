package com.antirat.mod.gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.font.TextAttribute;
import java.awt.geom.RoundRectangle2D;
import java.util.Map;

/**
 * Anti-RAT Boot Animation Screen.
 * Shows a fullscreen cinematic intro animation with shield logo, typing effect,
 * and smooth alpha fade before revealing the security gate window.
 * Emoji rendered using Segoe UI Emoji font for proper Windows display.
 */
public class BootAnimationScreen extends JWindow {

    private static final Color COLOR_BG = new Color(12, 14, 20);
    private static final Color COLOR_ACCENT = new Color(0, 230, 180);
    private static final Color COLOR_RED = new Color(245, 65, 85);
    private static final Color COLOR_TEXT = new Color(230, 235, 245);
    private static final Color COLOR_MUTED = new Color(100, 110, 130);

    // Emoji font for guaranteed rendering
    private static final Font EMOJI_FONT = resolveEmojiFont(64f);
    private static final Font EMOJI_FONT_SMALL = resolveEmojiFont(28f);
    private static final Font TITLE_FONT = new Font("Segoe UI", Font.BOLD, 28);
    private static final Font SUBTITLE_FONT = new Font("Segoe UI", Font.PLAIN, 14);
    private static final Font MONO_FONT = new Font("Consolas", Font.PLAIN, 13);

    private static Font resolveEmojiFont(float size) {
        // Try emoji-capable fonts in order of preference
        String[] emojiCandidates = {"Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", "Segoe UI Symbol", "Sans-Serif"};
        for (String name : emojiCandidates) {
            Font f = new Font(name, Font.PLAIN, (int) size);
            if (f.canDisplay('\uD83D') || f.canDisplayUpTo("🛡") == -1) {
                return f.deriveFont(size);
            }
        }
        return new Font("Segoe UI", Font.PLAIN, (int) size);
    }

    // Animation state
    private int tick = 0;
    private float shieldAlpha = 0f;
    private float titleAlpha = 0f;
    private float subtitleAlpha = 0f;
    private float barProgress = 0f;
    private float windowAlpha = 1f;
    private int typewriterIndex = 0;
    private boolean fadingOut = false;

    private final String TITLE_TEXT = "ANTI-RAT SECURITY SUITE";
    private final String[] BOOT_LINES = {
        "> Initializing Security Scanner...",
        "> Loading Malware Rule Engine...",
        "> Activating Behavioral Monitor...",
        "> Scanning Mods Directory...",
        "> Pre-Launch Gate Active."
    };
    private int bootLineIndex = 0;

    private final Runnable onComplete;
    private Timer animTimer;

    private final AnimationPanel animPanel;

    public BootAnimationScreen(Runnable onComplete) {
        this.onComplete = onComplete;
        setBackground(new Color(0, 0, 0, 0));
        setSize(Toolkit.getDefaultToolkit().getScreenSize());
        setLocationRelativeTo(null);

        animPanel = new AnimationPanel();
        setContentPane(animPanel);

        // Try to set shaped window for cleaner look
        try {
            setShape(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 0, 0));
        } catch (Exception ignored) {}

        // Set always on top
        setAlwaysOnTop(true);
    }

    public void startAnimation() {
        setVisible(true);
        toFront();
        requestFocus();

        animTimer = new Timer(16, new ActionListener() { // ~60fps
            @Override
            public void actionPerformed(ActionEvent e) {
                tick++;

                if (!fadingOut) {
                    // Phase 1: Shield fades in (0-60 ticks)
                    if (tick <= 60) {
                        shieldAlpha = Math.min(1f, tick / 50f);
                    }

                    // Phase 2: Title typewriter starts (tick 40+)
                    if (tick >= 40) {
                        titleAlpha = Math.min(1f, (tick - 40) / 30f);
                        if (tick % 3 == 0 && typewriterIndex < TITLE_TEXT.length()) {
                            typewriterIndex++;
                        }
                    }

                    // Phase 3: Subtitle and progress bar (tick 90+)
                    if (tick >= 90) {
                        subtitleAlpha = Math.min(1f, (tick - 90) / 30f);
                        barProgress = Math.min(1f, (tick - 90) / 120f);
                        int expectedLine = (int) (barProgress * BOOT_LINES.length);
                        bootLineIndex = Math.min(expectedLine, BOOT_LINES.length - 1);
                    }

                    // Phase 4: Start fade out when done (tick 230+)
                    if (tick >= 230) {
                        fadingOut = true;
                    }
                } else {
                    // Fade out
                    windowAlpha = Math.max(0f, windowAlpha - 0.045f);
                    if (windowAlpha <= 0f) {
                        animTimer.stop();
                        setVisible(false);
                        dispose();
                        onComplete.run();
                        return;
                    }
                }

                animPanel.repaint();
            }
        });

        animTimer.start();
    }

    private class AnimationPanel extends JPanel {

        public AnimationPanel() {
            setBackground(COLOR_BG);
            setOpaque(true);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
            g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);

            int W = getWidth();
            int H = getHeight();
            int cx = W / 2;
            int cy = H / 2;

            // -- Background gradient --
            GradientPaint bgGrad = new GradientPaint(0, 0, new Color(10, 12, 18), 0, H, new Color(16, 20, 30));
            g2.setPaint(bgGrad);
            g2.fillRect(0, 0, W, H);

            // -- Subtle grid lines --
            g2.setColor(new Color(30, 40, 55, 90));
            g2.setStroke(new BasicStroke(1f));
            for (int x = 0; x < W; x += 40) g2.drawLine(x, 0, x, H);
            for (int y = 0; y < H; y += 40) g2.drawLine(0, y, W, y);

            // -- Global alpha for fade out --
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, windowAlpha));

            // -- Shield Emoji (centered, large) --
            if (shieldAlpha > 0f) {
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, shieldAlpha * windowAlpha));
                // Glowing circle behind shield
                float glowRadius = 80f + (float)(Math.sin(tick * 0.05) * 6);
                int glowX = (int)(cx - glowRadius);
                int glowY = (int)(cy - 100 - glowRadius);
                for (int i = 5; i >= 0; i--) {
                    float r = glowRadius + i * 8;
                    g2.setColor(new Color(0, 230, 180, 15 - i * 2));
                    g2.fillOval((int)(cx - r), (int)(cy - 100 - r), (int)(r * 2), (int)(r * 2));
                }
                // Draw shield emoji with emoji font
                g2.setFont(EMOJI_FONT);
                g2.setColor(new Color(0, 230, 180));
                FontMetrics efm = g2.getFontMetrics();
                g2.drawString("\uD83D\uDEE1", cx - efm.stringWidth("\uD83D\uDEE1") / 2, cy - 55);
            }

            // -- Title typewriter text --
            if (titleAlpha > 0f && typewriterIndex > 0) {
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, titleAlpha * windowAlpha));
                g2.setFont(TITLE_FONT);
                g2.setColor(COLOR_TEXT);
                String visibleTitle = TITLE_TEXT.substring(0, typewriterIndex);
                FontMetrics tfm = g2.getFontMetrics();
                int tx = cx - tfm.stringWidth(visibleTitle) / 2;
                g2.drawString(visibleTitle, tx, cy + 20);

                // Blinking cursor
                if (typewriterIndex < TITLE_TEXT.length() || tick % 30 < 15) {
                    int cursorX = tx + tfm.stringWidth(visibleTitle);
                    g2.setColor(COLOR_ACCENT);
                    g2.fillRect(cursorX + 2, cy + 4, 3, 18);
                }

                // Accent underline
                int lineW = tfm.stringWidth(TITLE_TEXT);
                int lineX = cx - lineW / 2;
                GradientPaint accentLine = new GradientPaint(lineX, 0, new Color(0, 230, 180, 0), cx, 0, COLOR_ACCENT, true);
                g2.setPaint(accentLine);
                g2.setStroke(new BasicStroke(2f));
                g2.drawLine(lineX, cy + 26, lineX + lineW, cy + 26);
            }

            // -- Subtitle --
            if (subtitleAlpha > 0f) {
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, subtitleAlpha * windowAlpha));
                g2.setFont(SUBTITLE_FONT);
                g2.setColor(COLOR_MUTED);
                String sub = "Developed by Anti-RAT Security Team  |  Credits to MarkDev1337";
                FontMetrics sfm = g2.getFontMetrics();
                g2.drawString(sub, cx - sfm.stringWidth(sub) / 2, cy + 48);
            }

            // -- Progress Bar --
            if (barProgress > 0f) {
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, Math.min(1f, subtitleAlpha) * windowAlpha));
                int barW = 480;
                int barH = 4;
                int barX = cx - barW / 2;
                int barY = cy + 72;

                // Bar track
                g2.setColor(new Color(40, 50, 65));
                g2.fillRoundRect(barX, barY, barW, barH, barH, barH);

                // Bar fill with gradient
                int fillW = (int)(barW * barProgress);
                if (fillW > 0) {
                    GradientPaint barGrad = new GradientPaint(barX, 0, new Color(0, 200, 160), barX + fillW, 0, COLOR_ACCENT);
                    g2.setPaint(barGrad);
                    g2.fillRoundRect(barX, barY, fillW, barH, barH, barH);

                    // Glow tip
                    g2.setColor(new Color(255, 255, 255, 100));
                    g2.fillRoundRect(barX + fillW - 6, barY - 1, 8, barH + 2, barH, barH);
                }

                // -- Boot lines (monospace) --
                g2.setFont(MONO_FONT);
                int lineStartY = cy + 92;
                for (int i = 0; i <= bootLineIndex; i++) {
                    float lineAlpha = (i < bootLineIndex) ? 0.55f : 1f;
                    g2.setColor(new Color(
                        i < bootLineIndex ? COLOR_MUTED.getRed() : COLOR_ACCENT.getRed(),
                        i < bootLineIndex ? COLOR_MUTED.getGreen() : COLOR_ACCENT.getGreen(),
                        i < bootLineIndex ? COLOR_MUTED.getBlue() : COLOR_ACCENT.getBlue(),
                        (int)(255 * lineAlpha * windowAlpha)
                    ));
                    FontMetrics mfm = g2.getFontMetrics();
                    g2.drawString(BOOT_LINES[i], cx - mfm.stringWidth(BOOT_LINES[i]) / 2, lineStartY + i * 18);
                }
            }

            // -- Version tag bottom right --
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.4f * windowAlpha));
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            g2.setColor(COLOR_MUTED);
            g2.drawString("Anti-RAT v1.0.0 | Fabric 1.21.11 | Java 21", W - 260, H - 14);

            g2.dispose();
        }
    }
}
