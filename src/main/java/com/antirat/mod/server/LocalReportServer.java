package com.antirat.mod.server;

import com.antirat.mod.scanner.SecurityScanner;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Embedded HTTP Localhost Server for ByteGuard Web Security Reports.
 * Serves the Jarscanner static malware analyzer UI with pre-loaded JAR analysis data.
 */
public class LocalReportServer {

    private static HttpServer server;
    private static int port = 8888;
    private static final Map<String, SecurityScanner.SecurityReport> activeReports = new ConcurrentHashMap<>();
    private static File jarScannerWebDir;

    public static synchronized void start(File gameDir) {
        if (server != null) return;

        // Locate Jarscanner web assets folder
        File rootDir = gameDir != null ? gameDir : new File(".");
        jarScannerWebDir = new File(rootDir, "Jarscanner_-_Static_Malware_Analyzer/jarscanner_-_static_malware_analyzer");

        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            server.createContext("/", new StaticFileHandler());
            server.setExecutor(null);
            server.start();
            System.out.println("[ByteGuard LocalReportServer] Local web report server running at http://localhost:" + port + "/");
        } catch (Exception e) {
            System.err.println("[ByteGuard LocalReportServer Error] Failed to start server: " + e.getMessage());
        }
    }

    public static void registerReport(SecurityScanner.SecurityReport report) {
        if (report == null || report.metadata.getJarFile() == null) return;
        String id = report.metadata.getJarFile().getName();
        activeReports.put(id, report);
    }

    public static String getReportUrl(SecurityScanner.SecurityReport report) {
        if (report == null || report.metadata.getJarFile() == null) return "http://localhost:" + port + "/";
        return "http://localhost:" + port + "/#analysis:" + report.metadata.getJarFile().getName();
    }

    private static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/") || path.equals("/index.html")) {
                serveIndex(exchange);
                return;
            }

            // API Endpoint for getting pre-scanned mod data JSON
            if (path.startsWith("/api/report/")) {
                String jarName = path.substring("/api/report/".length());
                serveReportJson(exchange, jarName);
                return;
            }

            // API Endpoint for fetching raw JAR binary bytes for browser JSZip auto-load
            if (path.startsWith("/api/jar/")) {
                String jarName = path.substring("/api/jar/".length());
                serveJarFile(exchange, jarName);
                return;
            }

            // Static files (css, js, fonts)
            File file = new File(jarScannerWebDir, path.startsWith("/") ? path.substring(1) : path);
            if (file.exists() && !file.isDirectory()) {
                byte[] bytes = java.nio.file.Files.readAllBytes(file.toPath());
                String contentType = getContentType(file.getName());
                exchange.getResponseHeaders().set("Content-Type", contentType);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } else {
                String notFound = "404 Not Found";
                exchange.sendResponseHeaders(404, notFound.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(notFound.getBytes(StandardCharsets.UTF_8));
                }
            }
        }

        private void serveIndex(HttpExchange exchange) throws IOException {
            File indexFile = new File(jarScannerWebDir, "index.html");
            if (!indexFile.exists()) {
                String err = "Jarscanner web assets not found.";
                exchange.sendResponseHeaders(404, err.length());
                try (OutputStream os = exchange.getResponseBody()) { os.write(err.getBytes()); }
                return;
            }

            String html = java.nio.file.Files.readString(indexFile.toPath(), StandardCharsets.UTF_8);

            // Hide the header as requested ("remove the header of jar scanner just the body")
            // Inject CSS to hide header / drop zone during auto-analysis mode and auto-trigger report
            String customStyleAndScript = """
                <style>
                    header, .site-header, .header-container, div.header { display: none !important; }
                    body { padding-top: 10px !important; }
                </style>
                <script>
                    window.addEventListener('DOMContentLoaded', async () => {
                        if (window.location.hash.startsWith('#analysis:')) {
                            const jarName = decodeURIComponent(window.location.hash.substring(10));
                            try {
                                const res = await fetch('/api/jar/' + encodeURIComponent(jarName));
                                if (res.ok) {
                                    const blob = await res.blob();
                                    const file = new File([blob], jarName, { type: 'application/java-archive' });
                                    if (typeof handleFile === 'function') {
                                        handleFile(file);
                                    }
                                }
                            } catch(e) { console.error('Auto-load failed:', e); }
                        }
                    });
                </script>
                """;

            html = html.replace("</head>", customStyleAndScript + "</head>");

            byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private void serveReportJson(HttpExchange exchange, String jarName) throws IOException {
            SecurityScanner.SecurityReport report = activeReports.get(jarName);
            if (report == null) {
                exchange.sendResponseHeaders(404, 0);
                return;
            }

            String json = String.format("{\"modId\":\"%s\",\"name\":\"%s\",\"score\":%d,\"level\":\"%s\"}",
                report.metadata.getModId(), report.metadata.getName(), report.suspicionScore, report.suspicionLevel.label);

            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
        }

        private void serveJarFile(HttpExchange exchange, String jarName) throws IOException {
            SecurityScanner.SecurityReport report = activeReports.get(jarName);
            if (report == null || report.metadata.getJarFile() == null || !report.metadata.getJarFile().exists()) {
                exchange.sendResponseHeaders(404, 0);
                return;
            }

            File jarFile = report.metadata.getJarFile();
            byte[] bytes = java.nio.file.Files.readAllBytes(jarFile.toPath());
            exchange.getResponseHeaders().set("Content-Type", "application/java-archive");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
        }

        private String getContentType(String name) {
            String lower = name.toLowerCase();
            if (lower.endsWith(".html")) return "text/html; charset=UTF-8";
            if (lower.endsWith(".css"))  return "text/css; charset=UTF-8";
            if (lower.endsWith(".js"))   return "application/javascript; charset=UTF-8";
            if (lower.endsWith(".json")) return "application/json";
            if (lower.endsWith(".woff2")) return "font/woff2";
            if (lower.endsWith(".png")) return "image/png";
            return "application/octet-stream";
        }
    }
}
