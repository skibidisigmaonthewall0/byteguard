package com.antirat.mod.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Utility for logging Anti-RAT actions, pre-launch scan reports, and block events.
 * Logs are output both to stdout and persisted to .minecraft/anti-rat-logs.txt.
 */
public class Logger {
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static File logFile;
    private static final List<String> IN_MEMORY_LOGS = Collections.synchronizedList(new ArrayList<>());
    private static final int MAX_IN_MEMORY_LOGS = 1000;

    public static void init(File minecraftDir) {
        logFile = new File(minecraftDir, "anti-rat-logs.txt");
        try {
            if (!logFile.exists()) {
                logFile.createNewFile();
            }
            log("SYSTEM", "INIT", "Anti-RAT Security Log initialized at " + logFile.getAbsolutePath(), "INFO");
        } catch (IOException e) {
            System.err.println("[AntiRAT] Failed to initialize log file: " + e.getMessage());
        }
    }

    /**
     * Standard Anti-RAT format: [timestamp] [MOD_NAME] [ACTION_TYPE] [FILE/PATH/COMMAND] [ALLOWED/DENIED]
     */
    public static synchronized void logAction(String modName, String actionType, String target, boolean allowed) {
        String status = allowed ? "ALLOWED" : "DENIED";
        log(modName, actionType, target, status);
    }

    public static synchronized void log(String modName, String actionType, String target, String status) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        String formattedMessage = String.format("[%s] [%s] [%s] [%s] [%s]", timestamp, modName, actionType, target, status);

        System.out.println("[AntiRAT] " + formattedMessage);

        IN_MEMORY_LOGS.add(formattedMessage);
        if (IN_MEMORY_LOGS.size() > MAX_IN_MEMORY_LOGS) {
            IN_MEMORY_LOGS.remove(0);
        }

        if (logFile != null) {
            try (PrintWriter out = new PrintWriter(new FileWriter(logFile, true))) {
                out.println(formattedMessage);
            } catch (IOException e) {
                System.err.println("[AntiRAT] Could not write log to file: " + e.getMessage());
            }
        }
    }

    public static List<String> getRecentLogs() {
        return new ArrayList<>(IN_MEMORY_LOGS);
    }
}
