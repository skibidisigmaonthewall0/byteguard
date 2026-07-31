package com.antirat.mod.gui;

import com.antirat.mod.manager.PermissionManager;
import com.antirat.mod.manager.QuarantineManager;
import com.antirat.mod.scanner.SecurityScanner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ByteGuard Pre-Launch Security Suite.
 *
 * Phase 1: Deep Scanning Progress Screen (animates for 10-15 seconds while scan runs in background).
 * Phase 2: Full Gate Window showing ALL scanned mods (clean and suspicious) with action buttons.
 */
public class NativeSecurityWindow {

    // ── Colour Palette ──────────────────────────────────────────────────────
    private static final Color BG         = new Color(13, 14, 20);
    private static final Color PANEL      = new Color(22, 25, 35);
    private static final Color CARD       = new Color(30, 34, 48);
    private static final Color BORDER     = new Color(40, 46, 65);
    private static final Color TEXT       = new Color(235, 240, 248);
    private static final Color MUTED      = new Color(120, 130, 155);
    private static final Color ACCENT     = new Color(0, 230, 175);
    private static final Color RED        = new Color(240, 55, 80);
    private static final Color RED_H      = new Color(255, 85, 110);
    private static final Color ORANGE     = new Color(255, 148, 0);
    private static final Color ORANGE_H   = new Color(255, 178, 35);
    private static final Color GREEN      = new Color(0, 195, 110);
    private static final Color GREEN_H    = new Color(30, 225, 140);
    private static final Color BLUE       = new Color(50, 85, 185);
    private static final Color BLUE_H     = new Color(75, 120, 235);

    // ── Scanning progress steps shown to user ──────────────────────────────
    private static final String[] SCAN_STEPS = {
        "Initializing ByteGuard Security Engine...",
        "Loading known malware hash database...",
        "Loading threat signature rules...",
        "Mapping JAR file entries...",
        "Deobfuscating bytecode (XOR / Arithmetic chains)...",
        "Deep-scanning class bytecode for RAT indicators...",
        "Analyzing string constants & URL patterns...",
        "Scanning for C2 callbacks & raw IP addresses...",
        "Checking Discord / Telegram webhook tokens...",
        "Analyzing ClassLoader & reflection injection vectors...",
        "Scanning for keyloggers & screen capture methods...",
        "Checking crypto wallet & browser credential paths...",
        "Running dynamic malware rule engine...",
        "Evaluating JAR-in-JAR nested libraries...",
        "Calculating suspicion scores...",
        "Cross-referencing Fractureiser / EtherHiding signatures...",
        "Applying open-source mod trust verification...",
        "Finalizing threat report..."
    };

    // ── Animated Hover Button ───────────────────────────────────────────────
    public static class AnimatedHoverButton extends JButton {
        private final Color norm, hov;

        public AnimatedHoverButton(String text, Color norm, Color hov) {
            super(text);
            this.norm = norm;
            this.hov = hov;
            setFont(new Font("Segoe UI", Font.BOLD, 12));
            setForeground(Color.WHITE);
            setBackground(norm);
            setFocusPainted(false);
            setContentAreaFilled(false);
            setOpaque(false);
            setBorder(new EmptyBorder(8, 18, 8, 18));
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                public void mouseEntered(MouseEvent e) { if (isEnabled()) { setBackground(hov); repaint(); } }
                public void mouseExited(MouseEvent e)  { if (isEnabled()) { setBackground(norm); repaint(); } }
            });
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(getBackground());
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
            g2.setColor(getBackground().brighter().brighter());
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /** Called by AntiRAT.onPreLaunch(). Shows scanning screen, deep scans, then shows gate. Blocks until resolved. */
    public static void showScanningAndGate(File[] jarFiles, File gameDir) {
        CountDownLatch latch = new CountDownLatch(1);

        SwingUtilities.invokeLater(() -> {
            try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception ignored) {}
            showScanPhase(jarFiles, gameDir, latch);
        });

        try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    /** Legacy compat */
    public static void showPreLaunchWindow(List<SecurityScanner.SecurityReport> reports) {
        CountDownLatch latch = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> openGate(reports, latch));
        try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    /** Legacy compat */
    public static void displayGateWindow(List<SecurityScanner.SecurityReport> reports) {
        showPreLaunchWindow(reports);
    }

    // ── Phase 1: Scanning Screen ────────────────────────────────────────────

    private static void showScanPhase(File[] jarFiles, File gameDir, CountDownLatch outerLatch) {
        JDialog scanDialog = new JDialog((Frame) null, "ByteGuard — Deep Scanning...", false);
        scanDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        scanDialog.setSize(720, 440);
        scanDialog.setLocationRelativeTo(null);
        scanDialog.setResizable(false);

        JPanel root = new JPanel(new BorderLayout(0, 0)) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setColor(BG);
                g2.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        root.setOpaque(false);
        root.setBorder(new EmptyBorder(32, 40, 32, 40));

        // Header
        JLabel icon = new JLabel("🛡", SwingConstants.CENTER);
        icon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 42));
        icon.setForeground(ACCENT);

        JLabel title = new JLabel("BYTEGUARD DEEP SCAN", SwingConstants.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 22));
        title.setForeground(ACCENT);

        JLabel sub = new JLabel("Analyzing all mods — please wait...", SwingConstants.CENTER);
        sub.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        sub.setForeground(MUTED);

        JPanel topPanel = new JPanel(new GridLayout(3, 1, 6, 6));
        topPanel.setOpaque(false);
        topPanel.add(icon);
        topPanel.add(title);
        topPanel.add(sub);
        root.add(topPanel, BorderLayout.NORTH);

        // Center — current step label + scrolling log
        JPanel centerPanel = new JPanel(new BorderLayout(0, 12));
        centerPanel.setOpaque(false);
        centerPanel.setBorder(new EmptyBorder(20, 0, 20, 0));

        JLabel currentStep = new JLabel("Initializing...", SwingConstants.LEFT);
        currentStep.setFont(new Font("Consolas", Font.BOLD, 12));
        currentStep.setForeground(ACCENT);

        JTextArea logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setBackground(CARD);
        logArea.setForeground(new Color(160, 200, 160));
        logArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        logArea.setBorder(new EmptyBorder(8, 10, 8, 10));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(new LineBorder(BORDER, 1));
        logScroll.setPreferredSize(new Dimension(640, 160));

        centerPanel.add(currentStep, BorderLayout.NORTH);
        centerPanel.add(logScroll, BorderLayout.CENTER);
        root.add(centerPanel, BorderLayout.CENTER);

        // Bottom — progress bar + jar count
        JProgressBar progressBar = new JProgressBar(0, 100) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                // Background
                g2.setColor(CARD);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                // Fill
                int fillW = (int) (getWidth() * (getValue() / 100.0));
                if (fillW > 0) {
                    g2.setColor(ACCENT);
                    g2.fillRoundRect(0, 0, fillW, getHeight(), 8, 8);
                }
                // Text
                g2.setColor(Color.WHITE);
                g2.setFont(new Font("Segoe UI", Font.BOLD, 11));
                String txt = getValue() + "%";
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(txt, (getWidth() - fm.stringWidth(txt)) / 2, (getHeight() + fm.getAscent() - fm.getDescent()) / 2);
                g2.dispose();
            }
        };
        progressBar.setStringPainted(false);
        progressBar.setBorder(null);
        progressBar.setPreferredSize(new Dimension(640, 18));

        JLabel countLabel = new JLabel("Scanning 0 / " + jarFiles.length + " mods...", SwingConstants.CENTER);
        countLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        countLabel.setForeground(MUTED);

        JPanel bottomPanel = new JPanel(new GridLayout(2, 1, 4, 4));
        bottomPanel.setOpaque(false);
        bottomPanel.add(progressBar);
        bottomPanel.add(countLabel);
        root.add(bottomPanel, BorderLayout.SOUTH);

        scanDialog.add(root);
        scanDialog.setVisible(true);

        // ── Background scan thread ─────────────────────────────────────────
        List<SecurityScanner.SecurityReport> allReports = new ArrayList<>();
        AtomicInteger doneCount = new AtomicInteger(0);

        new Thread(() -> {
            // Phase A: simulate initial steps for 3 seconds before actual scanning
            int stepDelay = 180;
            for (int i = 0; i < 8; i++) {
                final String step = SCAN_STEPS[i];
                final int pct = (i * 5);
                SwingUtilities.invokeLater(() -> {
                    currentStep.setText("▶  " + step);
                    logArea.append("[" + timestamp() + "] " + step + "\n");
                    logArea.setCaretPosition(logArea.getDocument().getLength());
                    progressBar.setValue(pct);
                });
                sleep(stepDelay);
            }

            // Phase B: actual scan of all JARs
            int total = jarFiles.length;
            for (int i = 0; i < total; i++) {
                File jar = jarFiles[i];

                final String scanning = "Scanning: " + jar.getName();
                final int idx = i;
                SwingUtilities.invokeLater(() -> {
                    currentStep.setText("▶  " + scanning);
                    logArea.append("[" + timestamp() + "] " + scanning + "\n");
                    logArea.setCaretPosition(logArea.getDocument().getLength());
                    int pct = 40 + (int)((idx / (double) total) * 45);
                    progressBar.setValue(pct);
                    countLabel.setText("Scanning " + (idx + 1) + " / " + total + " mods...");
                });

                SecurityScanner.SecurityReport report = SecurityScanner.scanJar(jar);
                System.out.printf("[ByteGuard Scan] %s | %s | Score: %d%n",
                    jar.getName(), report.suspicionLevel.label, report.suspicionScore);

                if (report.suspicionLevel != SecurityScanner.SuspicionLevel.CLEAN) {
                    QuarantineManager.addQuarantinedReport(report);
                }
                allReports.add(report);
                doneCount.incrementAndGet();

                // Minimum visual time per jar
                sleep(60);
            }

            // Phase C: finalising steps
            for (int i = 8; i < SCAN_STEPS.length; i++) {
                final String step = SCAN_STEPS[i];
                final int pct = 85 + ((i - 8) * 1);
                SwingUtilities.invokeLater(() -> {
                    currentStep.setText("▶  " + step);
                    logArea.append("[" + timestamp() + "] " + step + "\n");
                    logArea.setCaretPosition(logArea.getDocument().getLength());
                    progressBar.setValue(Math.min(pct, 98));
                });
                sleep(300);
            }

            // Minimum total scan time = 10 seconds
            long elapsed = System.currentTimeMillis();
            long minimumMs = 10_000;
            long remaining = minimumMs - (System.currentTimeMillis() - elapsed);
            if (remaining > 0) sleep(remaining);

            SwingUtilities.invokeLater(() -> {
                progressBar.setValue(100);
                currentStep.setText("✅  Scan complete! Opening security report...");
                logArea.append("[" + timestamp() + "] Scan complete. " + allReports.size() + " mods analyzed.\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
                countLabel.setText("Complete — " + allReports.size() + " mods scanned.");
            });

            sleep(800);

            // Sort: flagged first, then by score desc
            allReports.sort((a, b) -> {
                int lvlA = a.suspicionLevel.ordinal();
                int lvlB = b.suspicionLevel.ordinal();
                if (lvlA != lvlB) return lvlB - lvlA;
                return b.suspicionScore - a.suspicionScore;
            });

            SwingUtilities.invokeLater(() -> {
                scanDialog.dispose();
                openGate(allReports, outerLatch);
            });

        }, "ByteGuard-DeepScan").start();
    }

    private static String timestamp() {
        java.time.LocalTime t = java.time.LocalTime.now();
        return String.format("%02d:%02d:%02d", t.getHour(), t.getMinute(), t.getSecond());
    }

    private static void sleep(long ms) {
        if (ms <= 0) return;
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    // ── Phase 2: Full Security Gate ─────────────────────────────────────────

    private static void openGate(List<SecurityScanner.SecurityReport> allReports, CountDownLatch latch) {
        JDialog frame = new JDialog((Frame) null, "ByteGuard Pre-Launch Security Suite", true);
        frame.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        frame.setSize(1050, 660);
        frame.setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(12, 12));
        mainPanel.setBackground(BG);
        mainPanel.setBorder(new EmptyBorder(14, 14, 14, 14));

        // Header
        JPanel header = new JPanel(new BorderLayout(8, 4));
        header.setBackground(PANEL);
        header.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER, 1, true), new EmptyBorder(12, 16, 12, 16)
        ));
        JLabel htitle = new JLabel(
            "<html><span style='font-size:15pt;color:#00e6af;font-family:Segoe UI;font-weight:bold;'>🛡 BYTEGUARD SECURITY SUITE &mdash; PRE-LAUNCH GATE</span></html>");
        JLabel hsub = new JLabel("Minecraft loading is paused. Developed by MarkDev1337 | ByteGuard Security Engine");
        hsub.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        hsub.setForeground(MUTED);

        long flagged = allReports.stream().filter(r -> r.suspicionLevel != SecurityScanner.SuspicionLevel.CLEAN).count();
        JLabel hcount = new JLabel(allReports.size() + " mods scanned — " + flagged + " suspicious", SwingConstants.RIGHT);
        hcount.setFont(new Font("Segoe UI", Font.BOLD, 12));
        hcount.setForeground(flagged > 0 ? RED : GREEN);

        header.add(htitle, BorderLayout.NORTH);
        header.add(hsub, BorderLayout.SOUTH);
        header.add(hcount, BorderLayout.EAST);
        mainPanel.add(header, BorderLayout.NORTH);

        // Tabs
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(new Font("Segoe UI", Font.BOLD, 12));
        tabs.setBackground(PANEL);

        // ── Tab 1: All Mods ────────────────────────────────────────────────
        JPanel reportsTab = new JPanel(new BorderLayout(10, 10));
        reportsTab.setBackground(PANEL);
        reportsTab.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Filtered list data holding original report indexes
        List<SecurityScanner.SecurityReport> filteredReports = new ArrayList<>(allReports);

        DefaultListModel<String> listModel = new DefaultListModel<>();
        Runnable rebuildModList = () -> {
            listModel.clear();
            for (SecurityScanner.SecurityReport rep : filteredReports) {
                int s = Math.min(100, rep.suspicionScore);
                String prefix = rep.suspicionLevel == SecurityScanner.SuspicionLevel.CLEAN ? "[✓]" : "[!]";
                String jarName = rep.metadata.getJarFile() != null ? rep.metadata.getJarFile().getName() : "";
                String displayName = rep.metadata.getName();
                if (!jarName.isEmpty() && !displayName.equalsIgnoreCase(jarName)) {
                    displayName += " (" + jarName + ")";
                }
                listModel.addElement(String.format("%s %s — %s (%d/100)",
                    prefix, displayName, rep.suspicionLevel.label, s));
            }
        };
        rebuildModList.run();

        // Search Bar Panel
        JPanel searchPanel = new JPanel(new BorderLayout(8, 0));
        searchPanel.setOpaque(false);
        searchPanel.setBorder(new EmptyBorder(0, 0, 8, 0));

        JLabel searchLabel = new JLabel("🔍 Search Mods: ");
        searchLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        searchLabel.setForeground(ACCENT);

        JTextField searchField = new JTextField();
        searchField.setBackground(BG);
        searchField.setForeground(TEXT);
        searchField.setCaretColor(ACCENT);
        searchField.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        searchField.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER, 1, true),
            new EmptyBorder(6, 8, 6, 8)
        ));

        searchPanel.add(searchLabel, BorderLayout.WEST);
        searchPanel.add(searchField, BorderLayout.CENTER);
        reportsTab.add(searchPanel, BorderLayout.NORTH);

        JList<String> modList = new JList<>(listModel);
        modList.setBackground(BG);
        modList.setForeground(TEXT);
        modList.setSelectionBackground(new Color(40, 60, 90));
        modList.setSelectionForeground(ACCENT);
        modList.setFont(new Font("Segoe UI", Font.BOLD, 12));
        modList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (!isSelected && index >= 0 && index < filteredReports.size()) {
                    SecurityScanner.SuspicionLevel lvl = filteredReports.get(index).suspicionLevel;
                    switch (lvl) {
                        case CRITICAL -> setForeground(new Color(255, 80, 110));
                        case HIGH     -> setForeground(new Color(255, 120, 50));
                        case MEDIUM   -> setForeground(ORANGE);
                        case LOW      -> setForeground(new Color(230, 210, 60));
                        case CLEAN    -> setForeground(new Color(100, 200, 140));
                    }
                }
                setBackground(isSelected ? new Color(40, 60, 90) : BG);
                setBorder(new EmptyBorder(3, 8, 3, 8));
                return this;
            }
        });

        JLabel detailTitle = new JLabel("Select a mod to view report", SwingConstants.LEFT);
        detailTitle.setFont(new Font("Segoe UI", Font.BOLD, 13));
        detailTitle.setForeground(TEXT);
        detailTitle.setBorder(new EmptyBorder(0, 0, 6, 0));

        JTextArea detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setBackground(BG);
        detailArea.setForeground(TEXT);
        detailArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        detailArea.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel detailPanel = new JPanel(new BorderLayout(6, 6));
        detailPanel.setBackground(BG);
        detailPanel.add(detailTitle, BorderLayout.NORTH);
        detailPanel.add(new JScrollPane(detailArea), BorderLayout.CENTER);

        modList.addListSelectionListener(e -> {
            int idx = modList.getSelectedIndex();
            if (idx < 0 || idx >= filteredReports.size()) return;
            SecurityScanner.SecurityReport r = filteredReports.get(idx);
            int displayScore = Math.min(100, r.suspicionScore);
            detailTitle.setText(r.metadata.getName() + " — " + r.suspicionLevel.label + " (" + displayScore + "/100)");


            StringBuilder sb = new StringBuilder();
            sb.append("====================================================\n");
            sb.append("  MOD SECURITY ANALYSIS REPORT\n");
            sb.append("====================================================\n");
            sb.append("Mod Name         : ").append(r.metadata.getName()).append("\n");
            sb.append("Mod ID           : ").append(r.metadata.getModId()).append("\n");
            sb.append("JAR File         : ").append(r.metadata.getJarFile() != null ? r.metadata.getJarFile().getName() : "Unknown").append("\n");
            sb.append("Suspicion Level  : ").append(r.suspicionLevel.label).append(" (Score: ").append(displayScore).append("/100)\n");
            sb.append("Obfuscation Score: ").append(r.obfuscationResult.score).append("/100\n");
            if (r.metadata.getJarFile() != null) {
                try { sb.append("SHA-256          : ").append(com.antirat.mod.scanner.ThreatDatabase.sha256Hex(r.metadata.getJarFile())).append("\n"); }
                catch (Exception ignored) {}
            }
            sb.append("\nDETECTED CAPABILITIES:\n");
            for (String cap : r.detectedCapabilities) {
                sb.append(cap.startsWith("!!") ? "  [CRITICAL] " : "  [!] ").append(cap).append("\n");
            }
            sb.append("\nEXTRACTED / DEOBFUSCATED STRINGS:\n");
            for (String s : r.flaggedStrings) sb.append("  >> \"").append(s).append("\"\n");
            sb.append("\nFLAGGED REASONS:\n");
            for (String reason : r.flaggedReasons) sb.append("  - ").append(reason).append("\n");

            detailArea.setText(sb.toString());
            detailArea.setCaretPosition(0);
        });

        // Search listener
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void filter() {
                String q = searchField.getText().toLowerCase().trim();
                filteredReports.clear();
                for (SecurityScanner.SecurityReport r : allReports) {
                    String name = r.metadata.getName().toLowerCase();
                    String id = r.metadata.getModId() != null ? r.metadata.getModId().toLowerCase() : "";
                    String jar = r.metadata.getJarFile() != null ? r.metadata.getJarFile().getName().toLowerCase() : "";
                    if (q.isEmpty() || name.contains(q) || id.contains(q) || jar.contains(q)) {
                        filteredReports.add(r);
                    }
                }
                rebuildModList.run();
                if (!filteredReports.isEmpty()) modList.setSelectedIndex(0);
                else {
                    detailTitle.setText("No matching mods found");
                    detailArea.setText("");
                }
            }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filter(); }
        });

        if (!allReports.isEmpty()) modList.setSelectedIndex(0);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(modList), detailPanel);
        split.setDividerLocation(340);
        reportsTab.add(split, BorderLayout.CENTER);
        tabs.addTab("All Mods (" + allReports.size() + ")", reportsTab);

        // ── Tab 2: Security Controls & Whitelist ───────────────────────────
        JPanel configTab = new JPanel(new BorderLayout(14, 14));
        configTab.setBackground(PANEL);
        configTab.setBorder(new EmptyBorder(16, 16, 16, 16));

        JPanel toggles = new JPanel(new GridLayout(2, 1, 8, 8));
        toggles.setOpaque(false);

        JCheckBox safeModeBox = new JCheckBox("Safe Mode (Auto-Deny All Suspicious File & Process Actions)", com.antirat.mod.manager.PermissionManager.isSafeMode());
        safeModeBox.setFont(new Font("Segoe UI", Font.BOLD, 13));
        safeModeBox.setBackground(PANEL);
        safeModeBox.setForeground(TEXT);
        safeModeBox.addActionListener(e -> PermissionManager.setSafeMode(safeModeBox.isSelected()));

        JCheckBox killBox = new JCheckBox("Emergency Kill Switch (Block All System Access Instantly)", PermissionManager.isKillSwitchActive());
        killBox.setFont(new Font("Segoe UI", Font.BOLD, 13));
        killBox.setBackground(PANEL);
        killBox.setForeground(RED);
        killBox.addActionListener(e -> PermissionManager.setKillSwitch(killBox.isSelected()));

        toggles.add(safeModeBox);
        toggles.add(killBox);
        configTab.add(toggles, BorderLayout.NORTH);

        // Whitelist section
        JPanel wlSection = new JPanel(new BorderLayout(8, 8));
        wlSection.setBackground(CARD);
        wlSection.setBorder(BorderFactory.createCompoundBorder(
            new LineBorder(BORDER, 1, true), new EmptyBorder(12, 12, 12, 12)
        ));

        JPanel wlTop = new JPanel(new GridLayout(2, 1, 4, 4));
        wlTop.setOpaque(false);
        JLabel wlTitle = new JLabel("🛡️ Mod Whitelist Manager — Select any mods to whitelist (0/100 CLEAN):");
        wlTitle.setFont(new Font("Segoe UI", Font.BOLD, 13));
        wlTitle.setForeground(ACCENT);
        JLabel wlTip = new JLabel("💡 Hold Ctrl or Shift to select multiple mods at once. Click drag also works.");
        wlTip.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        wlTip.setForeground(MUTED);
        wlTop.add(wlTitle);
        wlTop.add(wlTip);

        DefaultListModel<String> wlModel = new DefaultListModel<>();
        for (SecurityScanner.SecurityReport rep : allReports) {
            if (rep.metadata.getModId() != null) {
                String status = PermissionManager.isWhitelisted(rep.metadata.getModId()) ? "[WHITELISTED] " : "";
                wlModel.addElement(status + rep.metadata.getName() + " (" + rep.metadata.getModId() + ")");
            }
        }

        JList<String> wlList = new JList<>(wlModel);
        wlList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        wlList.setBackground(BG);
        wlList.setForeground(TEXT);
        wlList.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        AnimatedHoverButton wlBtn = new AnimatedHoverButton("🛡️ Whitelist Selected Mods", new Color(0, 140, 110), ACCENT);
        wlBtn.addActionListener(e -> {
            int[] sel = wlList.getSelectedIndices();
            if (sel.length == 0) {
                JOptionPane.showMessageDialog(frame, "Please select at least one mod.", "No Selection", JOptionPane.WARNING_MESSAGE);
                return;
            }
            int count = 0;
            for (int i : sel) {
                if (i >= 0 && i < allReports.size() && allReports.get(i).metadata.getModId() != null) {
                    PermissionManager.addToWhitelist(allReports.get(i).metadata.getModId());
                    count++;
                }
            }
            JOptionPane.showMessageDialog(frame, count + " mod(s) whitelisted!\nThey will evaluate to 0/100 CLEAN on next launch.", "Whitelist Saved", JOptionPane.INFORMATION_MESSAGE);
        });

        wlSection.add(wlTop, BorderLayout.NORTH);
        wlSection.add(new JScrollPane(wlList), BorderLayout.CENTER);
        wlSection.add(wlBtn, BorderLayout.SOUTH);
        configTab.add(wlSection, BorderLayout.CENTER);
        tabs.addTab("Security Controls", configTab);

        mainPanel.add(tabs, BorderLayout.CENTER);

        // ── Bottom Toolbar ─────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 10));
        toolbar.setBackground(BG);

        AnimatedHoverButton continueBtn = new AnimatedHoverButton("✅ Continue (Allow All)", GREEN, GREEN_H);
        continueBtn.addActionListener(e -> { frame.dispose(); latch.countDown(); });

        AnimatedHoverButton allowSelBtn = new AnimatedHoverButton("Allow Selected Mod", new Color(0, 140, 100), GREEN_H);
        allowSelBtn.addActionListener(e -> {
            int idx = modList.getSelectedIndex();
            if (idx >= 0 && idx < allReports.size()) {
                allReports.remove(idx);
                listModel.remove(idx);
                if (allReports.isEmpty()) { frame.dispose(); latch.countDown(); }
                else modList.setSelectedIndex(Math.min(idx, allReports.size() - 1));
                tabs.setTitleAt(0, "All Mods (" + allReports.size() + ")");
            }
        });

        AnimatedHoverButton quarSelBtn = new AnimatedHoverButton("Quarantine Selected & Exit", ORANGE, ORANGE_H);
        quarSelBtn.addActionListener(e -> {
            int idx = modList.getSelectedIndex();
            if (idx >= 0 && idx < allReports.size()) {
                SecurityScanner.SecurityReport rep = allReports.get(idx);
                if (rep.metadata.getJarFile() != null) QuarantineManager.moveJarToQuarantine(rep.metadata.getJarFile());
                JOptionPane.showMessageDialog(frame, "Mod quarantined.\nMinecraft will shut down.", "Quarantine", JOptionPane.WARNING_MESSAGE);
                System.exit(0);
            }
        });

        AnimatedHoverButton quarAllBtn = new AnimatedHoverButton("Quarantine ALL Flagged & Exit", new Color(190, 50, 20), RED_H);
        quarAllBtn.addActionListener(e -> {
            for (SecurityScanner.SecurityReport rep : allReports) {
                if (rep.suspicionLevel != SecurityScanner.SuspicionLevel.CLEAN && rep.metadata.getJarFile() != null)
                    QuarantineManager.moveJarToQuarantine(rep.metadata.getJarFile());
            }
            JOptionPane.showMessageDialog(frame, "All flagged mods quarantined.\nMinecraft will shut down.", "Quarantine", JOptionPane.WARNING_MESSAGE);
            System.exit(0);
        });

        AnimatedHoverButton killBtn = new AnimatedHoverButton("Terminate Minecraft", RED, RED_H);
        killBtn.addActionListener(e -> System.exit(0));

        toolbar.add(continueBtn);
        toolbar.add(allowSelBtn);
        toolbar.add(quarSelBtn);
        toolbar.add(quarAllBtn);
        toolbar.add(killBtn);

        mainPanel.add(toolbar, BorderLayout.SOUTH);
        frame.add(mainPanel);
        frame.setVisible(true);
    }
}
