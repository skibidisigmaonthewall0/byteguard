package com.antirat.mod.gui;

import com.antirat.mod.config.SettingsStorage;
import com.antirat.mod.manager.PermissionManager;
import com.antirat.mod.manager.QuarantineManager;
import com.antirat.mod.scanner.SecurityScanner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Premium Modern Dark-Theme Security Suite Window.
 * Features boot animation, smooth button hover animations, exact flagged strings inspector,
 * emoji rendering via Segoe UI Emoji font, and credits to MarkDev1337.
 */
public class NativeSecurityWindow {

    private static final Color COLOR_BG = new Color(18, 20, 26);
    private static final Color COLOR_PANEL = new Color(26, 29, 38);
    private static final Color COLOR_CARD = new Color(34, 38, 50);
    private static final Color COLOR_TEXT = new Color(240, 243, 246);
    private static final Color COLOR_TEXT_MUTED = new Color(140, 148, 165);

    // Emoji-capable font for proper Windows emoji rendering
    private static final Font EMOJI_FONT = resolveEmojiFont(18f);

    private static Font resolveEmojiFont(float size) {
        String[] candidates = {"Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji", "Segoe UI Symbol", "Dialog"};
        for (String name : candidates) {
            Font f = new Font(name, Font.PLAIN, (int) size);
            if (f.canDisplayUpTo("\uD83D\uDEE1") == -1) return f.deriveFont(size);
        }
        return new Font("Dialog", Font.PLAIN, (int) size);
    }

    /** Returns a JLabel that renders emoji correctly on Windows via Segoe UI Emoji font */
    private static JLabel emojiLabel(String text, float size, int style) {
        JLabel label = new JLabel(text);
        label.setFont(resolveEmojiFont(size).deriveFont(style));
        return label;
    }
    private static final Color COLOR_ACCENT = new Color(0, 230, 180);
    private static final Color COLOR_RED = new Color(245, 65, 85);
    private static final Color COLOR_RED_HOVER = new Color(255, 95, 115);
    private static final Color COLOR_ORANGE = new Color(255, 145, 0);
    private static final Color COLOR_ORANGE_HOVER = new Color(255, 175, 30);
    private static final Color COLOR_GREEN = new Color(0, 190, 110);
    private static final Color COLOR_GREEN_HOVER = new Color(30, 220, 140);

    /**
     * Modern Animated Hover Button with smooth cursor feedback and rounded borders.
     */
    private static class AnimatedHoverButton extends JButton {
        private Color normalColor;
        private Color hoverColor;

        public AnimatedHoverButton(String text, Color normalColor, Color hoverColor) {
            super(text);
            this.normalColor = normalColor;
            this.hoverColor = hoverColor;
            setFont(new Font("Segoe UI", Font.BOLD, 12));
            setForeground(Color.WHITE);
            setBackground(normalColor);
            setFocusPainted(false);
            setContentAreaFilled(false);
            setOpaque(true);
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(normalColor.brighter(), 1, true),
                new EmptyBorder(8, 16, 8, 16)
            ));

            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    setBackground(hoverColor);
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    setBackground(normalColor);
                }
            });
        }
    }

    public static void showPreLaunchWindow(List<SecurityScanner.SecurityReport> reportsInput) {
        if (reportsInput == null || reportsInput.isEmpty()) return;

        List<SecurityScanner.SecurityReport> activeReports = new ArrayList<>(reportsInput);
        CountDownLatch latch = new CountDownLatch(1);

        SwingUtilities.invokeLater(() -> {
            // Play boot animation first, then open security gate
            BootAnimationScreen bootAnim = new BootAnimationScreen(() -> {
                SwingUtilities.invokeLater(() -> openSecurityGate(activeReports, latch));
            });
            bootAnim.startAnimation();
        });

        try {
            System.out.println("[AntiRAT] Pausing game startup thread until user resolves Pre-Launch Security Gate window...");
            latch.await();
            System.out.println("[AntiRAT] User decision received. Resuming startup sequence...");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void openSecurityGate(List<SecurityScanner.SecurityReport> activeReports, CountDownLatch latch) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {
            }

            JDialog frame = new JDialog((Frame) null, "ByteGuard Pre-Launch Security Suite", true);
            frame.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
            frame.setSize(920, 620);
            frame.setLocationRelativeTo(null);

            JPanel mainPanel = new JPanel(new BorderLayout(14, 14));
            mainPanel.setBackground(COLOR_BG);
            mainPanel.setBorder(new EmptyBorder(18, 18, 18, 18));

            // Header Banner
            JPanel headerPanel = new JPanel(new BorderLayout(8, 8));
            headerPanel.setBackground(COLOR_PANEL);
            headerPanel.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(COLOR_CARD, 1, true),
                new EmptyBorder(12, 16, 12, 16)
            ));

            // Use HTML to allow mixed emoji + bold fonts in same label
            JLabel titleLabel = new JLabel(
                "<html><span style='font-family:Segoe UI Emoji;font-size:16pt;'>🛡</span>"
                + "<span style='font-family:Segoe UI;font-weight:bold;font-size:14pt;'> BYTEGUARD SECURITY SUITE &mdash; PRE-LAUNCH GATE</span></html>",
                SwingConstants.LEFT
            );
            titleLabel.setForeground(new Color(0, 230, 180));

            JLabel subtitleLabel = new JLabel("Minecraft loading is paused. Developed by MarkDev1337 | ByteGuard Security Engine", SwingConstants.LEFT);
            subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            subtitleLabel.setForeground(COLOR_TEXT_MUTED);

            headerPanel.add(titleLabel, BorderLayout.NORTH);
            headerPanel.add(subtitleLabel, BorderLayout.SOUTH);
            mainPanel.add(headerPanel, BorderLayout.NORTH);

            // Tabbed Pane
            JTabbedPane tabbedPane = new JTabbedPane();
            tabbedPane.setFont(new Font("Segoe UI", Font.BOLD, 12));
            tabbedPane.setBackground(COLOR_PANEL);
            tabbedPane.setForeground(Color.BLACK);

            // 1. Reports Tab
            JPanel reportsTab = new JPanel(new BorderLayout(12, 12));
            reportsTab.setBackground(COLOR_PANEL);
            reportsTab.setBorder(new EmptyBorder(12, 12, 12, 12));

            DefaultListModel<String> listModel = new DefaultListModel<>();
            for (SecurityScanner.SecurityReport rep : activeReports) {
                int displayScore = Math.min(100, rep.suspicionScore);
                listModel.addElement(String.format("[!] %s (%s) — Score: %d/100", rep.metadata.getName(), rep.metadata.getJarFile() != null ? rep.metadata.getJarFile().getName() : "jar", displayScore));
            }

            JList<String> reportJList = new JList<>(listModel);
            reportJList.setBackground(COLOR_BG);
            reportJList.setForeground(COLOR_TEXT);
            reportJList.setSelectionBackground(new Color(45, 65, 95));
            reportJList.setSelectionForeground(COLOR_ACCENT);
            reportJList.setFont(new Font("Segoe UI", Font.BOLD, 13));

            JTextArea detailsArea = new JTextArea();
            detailsArea.setEditable(false);
            detailsArea.setLineWrap(true);
            detailsArea.setWrapStyleWord(true);
            detailsArea.setBackground(COLOR_BG);
            detailsArea.setForeground(COLOR_TEXT);
            detailsArea.setFont(new Font("Consolas", Font.PLAIN, 12));
            detailsArea.setBorder(new EmptyBorder(10, 10, 10, 10));

            Runnable updateDetails = () -> {
                int idx = reportJList.getSelectedIndex();
                if (idx >= 0 && idx < activeReports.size()) {
                    SecurityScanner.SecurityReport r = activeReports.get(idx);
                    int displayScore = Math.min(100, r.suspicionScore);
                    StringBuilder sb = new StringBuilder();
                    sb.append("====================================================\n");
                    sb.append("  MOD SECURITY ANALYSIS REPORT\n");
                    sb.append("====================================================\n");
                    sb.append("Mod Name         : ").append(r.metadata.getName()).append("\n");
                    sb.append("Mod ID           : ").append(r.metadata.getModId()).append("\n");
                    sb.append("JAR File         : ").append(r.metadata.getJarFile() != null ? r.metadata.getJarFile().getName() : "Unknown").append("\n");
                    sb.append("Suspicion Level  : ").append(r.suspicionLevel.label).append(" (Score: ").append(displayScore).append("/100)\n");
                    sb.append("Obfuscation Score: ").append(r.obfuscationResult.score).append("/100\n");

                    // Compute and display SHA-256 hash
                    if (r.metadata.getJarFile() != null) {
                        try {
                            String sha256 = com.antirat.mod.scanner.ThreatDatabase.sha256Hex(r.metadata.getJarFile());
                            sb.append("SHA-256          : ").append(sha256).append("\n");
                            // Check if it matches known-bad database
                            if (com.antirat.mod.scanner.ThreatDatabase.getKnownBadHashes().containsKey(sha256)) {
                                sb.append("HASH STATUS      : !! KNOWN MALICIOUS JAR - ").append(
                                    com.antirat.mod.scanner.ThreatDatabase.getKnownBadHashes().get(sha256)).append("\n");
                            } else {
                                sb.append("HASH STATUS      : Not in known-bad database\n");
                            }
                        } catch (Exception e) {
                            sb.append("SHA-256          : (error computing hash)\n");
                        }
                    }
                    sb.append("\n");

                    sb.append("DETECTED CAPABILITIES:\n");
                    if (r.detectedCapabilities.isEmpty()) {
                        sb.append("  - None detected\n");
                    } else {
                        for (String cap : r.detectedCapabilities) {
                            // Prefix critical findings with a visual alert
                            String prefix = cap.startsWith("!!") ? "  [CRITICAL] " : "  [!] ";
                            sb.append(prefix).append(cap).append("\n");
                        }
                    }

                    sb.append("\nEXTRACTED / DEOBFUSCATED STRINGS:\n");
                    if (r.flaggedStrings == null || r.flaggedStrings.isEmpty()) {
                        sb.append("  - None extracted\n");
                    } else {
                        for (String str : r.flaggedStrings) {
                            sb.append("  >> \"").append(str).append("\"\n");
                        }
                    }

                    sb.append("\nFLAGGED REASONS:\n");
                    for (String reason : r.flaggedReasons) {
                        sb.append("  - ").append(reason).append("\n");
                    }

                    detailsArea.setText(sb.toString());
                    detailsArea.setCaretPosition(0); // Scroll to top
                } else {
                    detailsArea.setText("No mod selected.");
                }
            };

            reportJList.addListSelectionListener(e -> updateDetails.run());

            if (!activeReports.isEmpty()) {
                reportJList.setSelectedIndex(0);
                updateDetails.run();
            }

            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(reportJList), new JScrollPane(detailsArea));
            splitPane.setDividerLocation(320);
            reportsTab.add(splitPane, BorderLayout.CENTER);
            tabbedPane.addTab("Scanned Mods (" + activeReports.size() + ")", reportsTab);

            // 2. Settings & Security Controls Tab with Whitelist Manager
            JPanel configTab = new JPanel(new BorderLayout(14, 14));
            configTab.setBackground(COLOR_PANEL);
            configTab.setBorder(new EmptyBorder(16, 16, 16, 16));

            JPanel topOptions = new JPanel(new GridLayout(2, 1, 8, 8));
            topOptions.setOpaque(false);

            JCheckBox safeModeBox = new JCheckBox("Safe Mode (Auto-Deny All Suspicious File & Process Actions)", PermissionManager.isSafeMode());
            safeModeBox.setFont(new Font("Segoe UI", Font.BOLD, 13));
            safeModeBox.setBackground(COLOR_PANEL);
            safeModeBox.setForeground(COLOR_TEXT);
            safeModeBox.addActionListener(e -> PermissionManager.setSafeMode(safeModeBox.isSelected()));

            JCheckBox killSwitchBox = new JCheckBox("Emergency Kill Switch (Block All System Access Instantly)", PermissionManager.isKillSwitchActive());
            killSwitchBox.setFont(new Font("Segoe UI", Font.BOLD, 13));
            killSwitchBox.setBackground(COLOR_PANEL);
            killSwitchBox.setForeground(COLOR_RED);
            killSwitchBox.addActionListener(e -> PermissionManager.setKillSwitch(killSwitchBox.isSelected()));

            topOptions.add(safeModeBox);
            topOptions.add(killSwitchBox);
            configTab.add(topOptions, BorderLayout.NORTH);

            // Mod Whitelist Manager Section below Emergency Kill Switch
            JPanel whitelistSection = new JPanel(new BorderLayout(8, 8));
            whitelistSection.setBackground(COLOR_CARD);
            whitelistSection.setBorder(BorderFactory.createCompoundBorder(
                new LineBorder(COLOR_BG, 1, true),
                new EmptyBorder(12, 12, 12, 12)
            ));

            JLabel wlHeader = new JLabel("🛡️ Mod Whitelist Manager (Select mods to whitelist so they evaluate to 0/100 CLEAN):");
            wlHeader.setFont(new Font("Segoe UI", Font.BOLD, 13));
            wlHeader.setForeground(COLOR_ACCENT);

            DefaultListModel<String> wlListModel = new DefaultListModel<>();
            for (SecurityScanner.SecurityReport rep : activeReports) {
                if (rep.metadata.getModId() != null) {
                    String status = PermissionManager.isWhitelisted(rep.metadata.getModId()) ? "[WHITELISTED] " : "";
                    wlListModel.addElement(status + rep.metadata.getName() + " (" + rep.metadata.getModId() + ")");
                }
            }

            JList<String> wlJList = new JList<>(wlListModel);
            wlJList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            wlJList.setBackground(COLOR_BG);
            wlJList.setForeground(COLOR_TEXT);
            wlJList.setFont(new Font("Segoe UI", Font.PLAIN, 12));

            AnimatedHoverButton batchWhitelistBtn = new AnimatedHoverButton("🛡️ Whitelist Selected Mods", new Color(0, 150, 120), COLOR_ACCENT);
            batchWhitelistBtn.addActionListener(e -> {
                int[] selectedIndices = wlJList.getSelectedIndices();
                if (selectedIndices.length == 0) {
                    JOptionPane.showMessageDialog(frame, "Please select at least one mod from the list to whitelist.", "No Selection", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                int addedCount = 0;
                for (int i : selectedIndices) {
                    if (i >= 0 && i < activeReports.size()) {
                        SecurityScanner.SecurityReport rep = activeReports.get(i);
                        if (rep.metadata.getModId() != null) {
                            PermissionManager.addToWhitelist(rep.metadata.getModId());
                            addedCount++;
                        }
                    }
                }
                JOptionPane.showMessageDialog(frame, addedCount + " mod(s) have been added to your Whitelist!\nThey will evaluate to 0/100 CLEAN on launch.", "Whitelist Saved", JOptionPane.INFORMATION_MESSAGE);
            });

            whitelistSection.add(wlHeader, BorderLayout.NORTH);
            whitelistSection.add(new JScrollPane(wlJList), BorderLayout.CENTER);
            whitelistSection.add(batchWhitelistBtn, BorderLayout.SOUTH);

            configTab.add(whitelistSection, BorderLayout.CENTER);
            tabbedPane.addTab("Security Controls", configTab);

            mainPanel.add(tabbedPane, BorderLayout.CENTER);

            // Bottom Action Buttons Panel (Original Layout Restored)
            JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 10));
            actionPanel.setBackground(COLOR_BG);

            AnimatedHoverButton scanAgainBtn = new AnimatedHoverButton("Scan Again", new Color(50, 80, 160), new Color(70, 110, 210));
            scanAgainBtn.addActionListener(e -> {
                scanAgainBtn.setText("Scanning...");
                scanAgainBtn.setEnabled(false);
                new Thread(() -> {
                    try {
                        File modsDir = null;
                        if (!activeReports.isEmpty() && activeReports.get(0).metadata.getJarFile() != null) {
                            modsDir = activeReports.get(0).metadata.getJarFile().getParentFile();
                        }
                        if (modsDir == null || !modsDir.exists()) return;

                        List<SecurityScanner.SecurityReport> freshReports = new ArrayList<>();
                        File[] files = modsDir.listFiles((d, n) -> n.endsWith(".jar"));
                        if (files != null) {
                            for (File jar : files) {
                                String n = jar.getName().toLowerCase();
                                if (n.contains("byteguard") || n.contains("antirat")) continue;
                                SecurityScanner.SecurityReport report = SecurityScanner.scanJar(jar);
                                if (report.suspicionLevel == SecurityScanner.SuspicionLevel.HIGH ||
                                    report.suspicionLevel == SecurityScanner.SuspicionLevel.CRITICAL) {
                                    freshReports.add(report);
                                }
                            }
                        }

                        SwingUtilities.invokeLater(() -> {
                            activeReports.clear();
                            activeReports.addAll(freshReports);
                            listModel.clear();
                            for (SecurityScanner.SecurityReport fr : activeReports) {
                                int score = Math.min(100, fr.suspicionScore);
                                listModel.addElement(String.format("[!] %s (%s) — Score: %d/100", fr.metadata.getName(),
                                    fr.metadata.getJarFile() != null ? fr.metadata.getJarFile().getName() : "jar", score));
                            }
                            tabbedPane.setTitleAt(0, "Scanned Mods (" + activeReports.size() + ")");
                            scanAgainBtn.setText("Scan Again");
                            scanAgainBtn.setEnabled(true);
                            if (!activeReports.isEmpty()) {
                                reportJList.setSelectedIndex(0);
                            }
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            scanAgainBtn.setText("Scan Again");
                            scanAgainBtn.setEnabled(true);
                        });
                    }
                }, "ByteGuard-Rescan").start();
            });

            AnimatedHoverButton allowSelectedBtn = new AnimatedHoverButton("Allow Selected Mod", COLOR_GREEN, COLOR_GREEN_HOVER);
            allowSelectedBtn.addActionListener(e -> {
                int idx = reportJList.getSelectedIndex();
                if (idx >= 0 && idx < activeReports.size()) {
                    activeReports.remove(idx);
                    listModel.remove(idx);
                    if (activeReports.isEmpty()) {
                        frame.dispose();
                        latch.countDown();
                    } else {
                        reportJList.setSelectedIndex(Math.min(idx, activeReports.size() - 1));
                        tabbedPane.setTitleAt(0, "Scanned Mods (" + activeReports.size() + ")");
                    }
                }
            });

            AnimatedHoverButton quarantineSelectedBtn = new AnimatedHoverButton("Quarantine Selected & Exit", COLOR_ORANGE, COLOR_ORANGE_HOVER);
            quarantineSelectedBtn.addActionListener(e -> {
                int idx = reportJList.getSelectedIndex();
                if (idx >= 0 && idx < activeReports.size()) {
                    SecurityScanner.SecurityReport rep = activeReports.get(idx);
                    if (rep.metadata.getJarFile() != null) {
                        QuarantineManager.moveJarToQuarantine(rep.metadata.getJarFile());
                    }
                    JOptionPane.showMessageDialog(frame, "Mod " + rep.metadata.getName() + " moved to .minecraft/quarantine.\nMinecraft will now shut down to prevent execution.", "Quarantine Complete", JOptionPane.WARNING_MESSAGE);
                    System.exit(0);
                }
            });

            AnimatedHoverButton quarantineAllBtn = new AnimatedHoverButton("Quarantine ALL Mods & Exit", new Color(190, 50, 20), COLOR_RED_HOVER);
            quarantineAllBtn.addActionListener(e -> {
                for (SecurityScanner.SecurityReport rep : activeReports) {
                    if (rep.metadata.getJarFile() != null) {
                        QuarantineManager.moveJarToQuarantine(rep.metadata.getJarFile());
                    }
                }
                JOptionPane.showMessageDialog(frame, "All flagged mods moved to .minecraft/quarantine.\nMinecraft will now shut down to protect your system.", "Quarantine Complete", JOptionPane.WARNING_MESSAGE);
                System.exit(0);
            });

            AnimatedHoverButton exitBtn = new AnimatedHoverButton("Terminate Minecraft", COLOR_RED, COLOR_RED_HOVER);
            exitBtn.addActionListener(e -> {
                System.out.println("[ByteGuard] User terminated Minecraft execution from Security Gate.");
                System.exit(0);
            });

            actionPanel.add(scanAgainBtn);
            actionPanel.add(allowSelectedBtn);
            actionPanel.add(quarantineSelectedBtn);
            actionPanel.add(quarantineAllBtn);
            actionPanel.add(exitBtn);

            mainPanel.add(actionPanel, BorderLayout.SOUTH);

            frame.add(mainPanel);
            frame.setVisible(true);
        });
    }
}
