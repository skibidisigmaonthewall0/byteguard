package com.antirat.mod.server;

import com.antirat.mod.scanner.ObfuscationDetector;
import com.antirat.mod.scanner.SecurityScanner;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Embedded Localhost Web Server serving a 1:1 Jarscanner.org full-screen report interface.
 * Features 2x2 grid layout, dark grid background, glowing risk progress bar, and extracted token inspector.
 */
public class LocalReportServer {

    private static HttpServer server;
    private static int activePort = 8999;
    private static List<SecurityScanner.SecurityReport> activeReports;

    public static synchronized void startAndOpenReport(List<SecurityScanner.SecurityReport> reports) {
        activeReports = reports;
        try {
            if (server == null) {
                for (int p = 8999; p <= 9005; p++) {
                    try {
                        server = HttpServer.create(new InetSocketAddress("localhost", p), 0);
                        activePort = p;
                        break;
                    } catch (IOException ignored) {}
                }
                if (server != null) {
                    server.createContext("/", new ReportHandler());
                    server.setExecutor(null);
                    server.start();
                    System.out.println("[ByteGuard Server] Jarscanner web report server running at http://localhost:" + activePort + "/");
                }
            }

            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI("http://localhost:" + activePort + "/"));
            }
        } catch (Exception e) {
            System.err.println("[ByteGuard Server] Failed to start report server: " + e.getMessage());
        }
    }

    private static class ReportHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (activeReports == null || activeReports.isEmpty()) {
                String emptyHtml = "<html><body style='background:#0a0c10;color:#fff;font-family:sans-serif;text-align:center;padding:100px;'><h2>No active threat reports found. All mods CLEAN!</h2></body></html>";
                sendResponse(exchange, emptyHtml);
                return;
            }

            SecurityScanner.SecurityReport report = activeReports.get(0);
            String html = buildJarscannerHtml(report);
            sendResponse(exchange, html);
        }

        private void sendResponse(HttpExchange exchange, String html) throws IOException {
            byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    private static String buildJarscannerHtml(SecurityScanner.SecurityReport report) {
        String jarName = report.metadata.getJarFile() != null ? report.metadata.getJarFile().getName().toUpperCase() : "BYTEGUARD-SCANNED-MOD.JAR";
        int score = Math.min(100, report.suspicionScore);
        boolean isMalware = score >= 50;

        String riskLabel = isMalware ? "CRITICAL RISK" : "CLEAN";
        String riskColor = isMalware ? "#2a9d8f" : "#00e6b4";
        String riskBannerBg = isMalware ? "linear-gradient(180deg, #59161a 0%, #2b0b0e 100%)" : "linear-gradient(180deg, #093b2a 0%, #041f16 100%)";
        String progressBg = isMalware ? "linear-gradient(90deg, #ff4d4d 0%, #ff1a1a 100%)" : "linear-gradient(90deg, #00e6b4 0%, #00b386 100%)";

        ObfuscationDetector.ObfuscationResult obf = report.obfuscationResult;
        String obfName = obf.score >= 50 ? "Barcode / Heavy Obfuscation" : obf.score >= 35 ? "Krypton Obfuscator" : "None";
        String obfDesc = obf.score >= 35 ? "Code is hidden or runs outside the JVM sandbox." : "Standard bytecode — no heavy obfuscation detected.";

        // 1. Malware Families
        StringBuilder familiesHtml = new StringBuilder();
        for (String cap : report.detectedCapabilities) {
            if (cap.contains("KNOWN MALWARE FAMILY")) {
                familiesHtml.append(String.format("""
                    <div style='margin-bottom:12px;'>
                        <div style='color:#fff;font-weight:bold;font-size:13px;'>%s</div>
                        <div style='color:#8a94a6;font-size:12px;margin-top:2px;'>Matches known RAT / infostealer signature pattern.</div>
                    </div>
                """, escapeHtml(cap)));
            }
        }
        if (familiesHtml.length() == 0) {
            familiesHtml.append("<div style='color:#8a94a6;font-size:13px;'>No specific malware family signatures matched.</div>");
        }

        // 2. Webhooks & Tokens
        StringBuilder secretsHtml = new StringBuilder();
        for (String s : report.flaggedStrings) {
            if (s.contains("http") || s.contains("webhook") || s.contains("token") || s.contains("mfa.") || s.contains("bot")) {
                secretsHtml.append(String.format("<div style='color:#64dfdf;font-size:12px;font-family:monospace;margin-bottom:6px;'>%s</div>", escapeHtml(s)));
            }
        }
        if (secretsHtml.length() == 0) {
            secretsHtml.append("<div style='color:#8a94a6;font-size:13px;'>No unmasked webhooks or bot tokens found.</div>");
        }

        // 3. Network & IP Reputation
        StringBuilder networkHtml = new StringBuilder();
        for (String s : report.flaggedStrings) {
            if (s.contains("[ETH-RPC]") || s.contains("c2") || s.contains("pastebin") || s.contains("gofile")) {
                networkHtml.append(String.format("<div style='color:#ff9e3b;font-size:12px;font-family:monospace;margin-bottom:6px;'>%s</div>", escapeHtml(s)));
            }
        }
        if (networkHtml.length() == 0) {
            networkHtml.append("<div style='color:#8a94a6;font-size:13px;'>No suspicious C2 domains or RPC endpoints found.</div>");
        }

        // 4. Suspicious Logic & Native Files
        StringBuilder logicHtml = new StringBuilder();
        for (String cap : report.detectedCapabilities) {
            if (!cap.contains("KNOWN MALWARE FAMILY")) {
                logicHtml.append(String.format("""
                    <div style='margin-bottom:10px;font-size:12px;font-family:monospace;'>
                        <span style='color:#fff;font-weight:bold;'>%s</span>
                    </div>
                """, escapeHtml(cap)));
            }
        }
        if (logicHtml.length() == 0) {
            logicHtml.append("<div style='color:#8a94a6;font-size:13px;'>No suspicious bytecode logic flagged.</div>");
        }

        return String.format("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Jarscanner — Static Malware Analysis</title>
                <style>
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body {
                        background-color: #060709;
                        background-image: radial-gradient(#151821 1px, transparent 1px);
                        background-size: 20px 20px;
                        color: #e0e6ed;
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                        padding: 40px 20px;
                        display: flex;
                        justify-content: center;
                    }
                    .main-wrapper { max-width: 1050px; width: 100%%; }
                    .header-bar {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 30px;
                    }
                    .logo-title { font-size: 24px; font-weight: 900; letter-spacing: -0.5px; color: #fff; }
                    .nav-menu { display: flex; gap: 24px; font-size: 14px; color: #7f8b9e; font-weight: 500; }
                    .nav-menu span:hover { color: #fff; cursor: pointer; }
                    .discord-btn {
                        background: #141722;
                        border: 1px solid #282e42;
                        color: #a9b5c7;
                        padding: 6px 16px;
                        border-radius: 6px;
                        font-size: 13px;
                        font-weight: 600;
                    }
                    .box-card {
                        background: #0d0f15;
                        border: 1px solid #1c212e;
                        border-radius: 8px;
                        padding: 20px;
                        margin-bottom: 18px;
                    }
                    .obf-banner { text-align: center; padding: 22px; }
                    .obf-head { font-size: 16px; font-weight: 800; color: #fff; letter-spacing: 0.5px; }
                    .obf-sub { font-size: 13px; color: #7f8b9e; margin-top: 6px; }
                    .malware-banner {
                        background: %s;
                        border: 1px solid #731e24;
                        border-radius: 10px;
                        padding: 28px 20px 20px 20px;
                        text-align: center;
                        margin-bottom: 18px;
                        box-shadow: 0 0 40px rgba(255, 30, 60, 0.15);
                    }
                    .malware-text { font-size: 26px; font-weight: 900; color: #ffffff; letter-spacing: 1px; }
                    .risk-text { font-size: 18px; font-weight: 800; color: %s; margin-top: 10px; }
                    .progress-track {
                        width: 100%%;
                        height: 8px;
                        background: #1f0a0d;
                        border-radius: 4px;
                        margin-top: 20px;
                        overflow: hidden;
                    }
                    .progress-fill {
                        height: 100%%;
                        width: %d%%;
                        background: %s;
                        border-radius: 4px;
                    }
                    .explorer-bar {
                        background: #0d0f15;
                        border: 1px solid #1c212e;
                        border-radius: 8px;
                        padding: 14px 20px;
                        font-family: monospace;
                        font-size: 13px;
                        color: #ff9e3b;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 18px;
                    }
                    .grid-2x2 {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 18px;
                        margin-bottom: 24px;
                    }
                    .grid-card {
                        background: #0d0f15;
                        border: 1px solid #1c212e;
                        border-radius: 8px;
                        padding: 20px;
                        min-height: 180px;
                        max-height: 300px;
                        overflow-y: auto;
                    }
                    .card-header {
                        font-size: 12px;
                        font-weight: 800;
                        color: #7f8b9e;
                        text-transform: uppercase;
                        letter-spacing: 0.8px;
                        margin-bottom: 14px;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }
                    .bottom-btn {
                        width: 100%%;
                        background: #12151f;
                        border: 1px solid #222838;
                        color: #a9b5c7;
                        padding: 14px;
                        border-radius: 8px;
                        text-align: center;
                        font-size: 14px;
                        font-weight: 700;
                        cursor: pointer;
                        transition: all 0.2s ease;
                    }
                    .bottom-btn:hover { background: #1a1e2d; color: #fff; }
                </style>
            </head>
            <body>
                <div class="main-wrapper">
                    <!-- Top Bar -->
                    <div class="header-bar">
                        <div class="logo-title">Jarscanner <span style="font-size:12px;color:#00e6b4;font-weight:600;margin-left:8px;">by ByteGuard</span></div>
                        <div class="nav-menu">
                            <span>Tools</span>
                            <span>Telegram</span>
                            <span>Webhooks</span>
                            <span>Team</span>
                        </div>
                        <div class="discord-btn">Discord</div>
                    </div>

                    <!-- Obfuscation Card -->
                    <div class="box-card obf-banner">
                        <div class="obf-head">OBFUSCATION DETECTED: %s</div>
                        <div class="obf-sub">%s</div>
                    </div>

                    <!-- Malware Detected Risk Banner -->
                    <div class="malware-banner">
                        <div class="malware-text">%s</div>
                        <div class="risk-text">%s - Risk Score: %d/100</div>
                        <div class="progress-track">
                            <div class="progress-fill"></div>
                        </div>
                    </div>

                    <!-- Internal File Explorer -->
                    <div class="explorer-bar">
                        <span>📁 INTERNAL FILE EXPLORER | %s</span>
                        <span style="color:#7f8b9e;font-size:12px;">Press To View ▼</span>
                    </div>

                    <!-- 2x2 Detail Cards Grid -->
                    <div class="grid-2x2">
                        <!-- Card 1: Detected Malware Families -->
                        <div class="grid-card">
                            <div class="card-header">💥 DETECTED MALWARE FAMILIES</div>
                            %s
                        </div>

                        <!-- Card 2: Webhooks & Telegram Tokens -->
                        <div class="grid-card">
                            <div class="card-header">🔗 WEBHOOKS & TELEGRAM TOKENS</div>
                            %s
                        </div>

                        <!-- Card 3: Network & IP Reputation -->
                        <div class="grid-card">
                            <div class="card-header">🌐 NETWORK & IP REPUTATION</div>
                            %s
                        </div>

                        <!-- Card 4: Suspicious Logic & Native Files -->
                        <div class="grid-card">
                            <div class="card-header">&lt;/&gt; SUSPICIOUS LOGIC & NATIVE FILES</div>
                            %s
                        </div>
                    </div>

                    <!-- Bottom Button -->
                    <div class="bottom-btn">Analyze New File</div>
                </div>
            </body>
            </html>
        """,
        riskBannerBg, riskColor, score, progressBg,
        escapeHtml(obfName), escapeHtml(obfDesc),
        isMalware ? "MALWARE DETECTED" : "NO MALWARE DETECTED",
        riskLabel, score,
        escapeHtml(jarName),
        familiesHtml.toString(),
        secretsHtml.toString(),
        networkHtml.toString(),
        logicHtml.toString()
        );
    }

    private static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
