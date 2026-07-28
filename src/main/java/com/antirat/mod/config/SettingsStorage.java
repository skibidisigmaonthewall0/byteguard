package com.antirat.mod.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Handles JSON persistence for Anti-RAT configuration, permissions, whitelist, and blacklist.
 */
public class SettingsStorage {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static File configFile;

    public static class ConfigData {
        public boolean safeMode = false;
        public boolean emergencyKillSwitch = false;
        public String defaultModBehavior = "ASK"; // ASK, ALWAYS_ALLOW, ALWAYS_DENY
        public int keybindScanGUI = 344; // Default: Right Shift (GLFW_KEY_RIGHT_SHIFT = 344)

        public Set<String> whitelistMods = new HashSet<>();
        public Set<String> blacklistMods = new HashSet<>();
        
        // Maps key (modId + ":" + action + ":" + path) -> decision ("ALLOW" / "DENY")
        public Map<String, String> rememberedPermissions = new HashMap<>();

        // Maps modId -> default behavior overriding global setting ("ASK", "ALWAYS_ALLOW", "ALWAYS_DENY")
        public Map<String, String> perModBehavior = new HashMap<>();
    }

    private static ConfigData data = new ConfigData();

    public static void init(File configDir) {
        configFile = new File(configDir, "antirat.json");
        load();
    }

    public static ConfigData getData() {
        return data;
    }

    public static void load() {
        if (configFile == null || !configFile.exists()) {
            save();
            return;
        }
        try (FileReader reader = new FileReader(configFile)) {
            ConfigData loaded = GSON.fromJson(reader, ConfigData.class);
            if (loaded != null) {
                data = loaded;
            }
        } catch (IOException e) {
            System.err.println("[AntiRAT] Failed to load config: " + e.getMessage());
        }
    }

    public static void save() {
        if (configFile == null) return;
        try {
            if (!configFile.getParentFile().exists()) {
                configFile.getParentFile().mkdirs();
            }
            try (FileWriter writer = new FileWriter(configFile)) {
                GSON.toJson(data, writer);
            }
        } catch (IOException e) {
            System.err.println("[AntiRAT] Failed to save config: " + e.getMessage());
        }
    }

    public static String exportJson() {
        return GSON.toJson(data);
    }

    public static boolean importJson(String json) {
        try {
            ConfigData imported = GSON.fromJson(json, ConfigData.class);
            if (imported != null) {
                data = imported;
                save();
                return true;
            }
        } catch (Exception e) {
            System.err.println("[AntiRAT] Error importing JSON config: " + e.getMessage());
        }
        return false;
    }
}
