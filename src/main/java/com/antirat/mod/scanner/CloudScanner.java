package com.antirat.mod.scanner;

import java.io.*;
import java.net.*;
import java.net.http.*;
import java.security.*;
import java.time.Duration;
import java.util.*;

/**
 * CloudScanner — Modrinth Official Hash Verification
 *
 * Uses the free, keyless Modrinth API to verify whether a JAR matches
 * its officially published version. No API key required.
 *
 * If the file IS on Modrinth → verified authentic (score bonus).
 * If the file is NOT on Modrinth → unknown origin (not automatically flagged, but noted).
 */
public class CloudScanner {

    public static class CloudScanResult {
        public boolean checkedModrinth   = false;
        public boolean isOnModrinth      = false;
        public String  modrinthProject   = null;
        public String  modrinthVersion   = null;
        public int     totalScoreAdded   = 0;
        public final List<String> cloudCapabilities = new ArrayList<>();
        public final List<String> cloudReasons      = new ArrayList<>();
    }

    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(4))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();

    // ── Public API ──────────────────────────────────────────────────────────

    public static CloudScanResult scan(File jarFile) {
        CloudScanResult result = new CloudScanResult();
        if (jarFile == null || !jarFile.exists()) return result;

        Thread modrinthThread = new Thread(() -> checkModrinth(result, jarFile));
        modrinthThread.setDaemon(true);
        modrinthThread.start();
        try { modrinthThread.join(5000); } catch (InterruptedException ignored) {}

        return result;
    }

    // ── Modrinth Verification ───────────────────────────────────────────────

    private static void checkModrinth(CloudScanResult result, File jarFile) {
        try {
            result.checkedModrinth = true;

            // Modrinth supports sha1 and sha512 — try sha512 first (more unique)
            String[] algos  = {"sha512", "sha1"};
            String[] hashes = {hashFile(jarFile, "SHA-512"), hashFile(jarFile, "SHA-1")};

            String responseBody = null;
            for (int i = 0; i < algos.length; i++) {
                if (hashes[i] == null) continue;
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.modrinth.com/v2/version_file/"
                        + hashes[i] + "?algorithm=" + algos[i]))
                    .header("User-Agent",
                        "ByteGuard-SecurityScanner/1.0 (github.com/skibidisigmaonthewall0/byteguard)")
                    .timeout(Duration.ofSeconds(4))
                    .GET()
                    .build();

                HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() == 200) {
                    responseBody = resp.body();
                    break;
                }
            }

            if (responseBody == null) {
                // Not on Modrinth — could be CurseForge, GitHub, or completely custom
                result.cloudCapabilities.add("Not found on Modrinth registry");
                return;
            }

            result.isOnModrinth  = true;
            result.modrinthProject = jsonString(responseBody, "project_id");
            result.modrinthVersion = jsonString(responseBody, "name");

            result.cloudCapabilities.add(
                "✓ Modrinth Verified — Project: " + result.modrinthProject
                + " | Version: " + result.modrinthVersion);
            result.cloudReasons.add(
                "JAR hash matches official Modrinth release — file is authentic and unmodified.");

            // Verified on Modrinth = strong authenticity signal (reduce score)
            result.totalScoreAdded -= 20;

        } catch (Exception e) {
            // Network unavailable, timeout, etc — fail silently and keep local score
        }
    }

    // ── Minimal JSON parser (no external deps) ─────────────────────────────

    private static String jsonString(String json, String key) {
        try {
            String pattern = "\"" + key + "\":\"";
            int start = json.indexOf(pattern);
            if (start < 0) return null;
            start += pattern.length();
            int end = json.indexOf("\"", start);
            return end > start ? json.substring(start, end) : null;
        } catch (Exception e) { return null; }
    }

    // ── Hash utilities ──────────────────────────────────────────────────────

    private static String hashFile(File f, String algo) {
        try (InputStream is = new FileInputStream(f)) {
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) md.update(buf, 0, n);
            return bytesToHex(md.digest());
        } catch (Exception e) { return null; }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
