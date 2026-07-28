package com.antirat.mod.manager;

import com.antirat.mod.config.SettingsStorage;
import com.antirat.mod.util.Logger;

/**
 * Core permission decision engine. Checks whitelist, blacklist, safe mode, kill switch,
 * auto-deny rules, and remembered user prompt decisions.
 */
public class PermissionManager {

    public enum Decision {
        ALLOW,
        DENY,
        ASK
    }

    public static boolean isSafeMode() {
        return SettingsStorage.getData().safeMode;
    }

    public static void setSafeMode(boolean enabled) {
        SettingsStorage.getData().safeMode = enabled;
        SettingsStorage.save();
        Logger.log("SYSTEM", "CONFIG", "Safe Mode set to: " + enabled, "INFO");
    }

    public static boolean isKillSwitchActive() {
        return SettingsStorage.getData().emergencyKillSwitch;
    }

    public static void setKillSwitch(boolean active) {
        SettingsStorage.getData().emergencyKillSwitch = active;
        SettingsStorage.save();
        Logger.log("SYSTEM", "CONFIG", "Emergency Kill Switch set to: " + active, active ? "ACTIVE" : "INACTIVE");
    }

    public static void addToWhitelist(String modId) {
        SettingsStorage.getData().whitelistMods.add(modId);
        SettingsStorage.getData().blacklistMods.remove(modId);
        SettingsStorage.save();
        Logger.log("SYSTEM", "PERM", "Added to Whitelist: " + modId, "ALLOWED");
    }

    public static void removeFromWhitelist(String modId) {
        SettingsStorage.getData().whitelistMods.remove(modId);
        SettingsStorage.save();
    }

    public static void addToBlacklist(String modId) {
        SettingsStorage.getData().blacklistMods.add(modId);
        SettingsStorage.getData().whitelistMods.remove(modId);
        SettingsStorage.save();
        Logger.log("SYSTEM", "PERM", "Added to Blacklist: " + modId, "DENIED");
    }

    public static void removeFromBlacklist(String modId) {
        SettingsStorage.getData().blacklistMods.remove(modId);
        SettingsStorage.save();
    }

    public static void rememberDecision(String modId, String action, String targetPath, boolean allow) {
        String key = modId + ":" + action + ":" + targetPath.toLowerCase();
        String decision = allow ? "ALLOW" : "DENY";
        SettingsStorage.getData().rememberedPermissions.put(key, decision);
        SettingsStorage.save();
    }

    /**
     * Evaluates access request for a mod + action + target path.
     */
    public static Decision evaluatePermission(String modId, String action, String targetPath) {
        // 1. Emergency Kill Switch active -> Instant Deny
        if (isKillSwitchActive()) {
            return Decision.DENY;
        }

        // 2. Safe Mode active -> Auto Deny everything suspicious
        if (isSafeMode()) {
            return Decision.DENY;
        }

        // 3. Check Blacklist
        if (SettingsStorage.getData().blacklistMods.contains(modId)) {
            return Decision.DENY;
        }

        // 4. Check Whitelist
        if (SettingsStorage.getData().whitelistMods.contains(modId)) {
            return Decision.ALLOW;
        }

        // 5. Check Per-Mod Custom Default Behavior
        if (SettingsStorage.getData().perModBehavior.containsKey(modId)) {
            String behavior = SettingsStorage.getData().perModBehavior.get(modId);
            if ("ALWAYS_ALLOW".equalsIgnoreCase(behavior)) return Decision.ALLOW;
            if ("ALWAYS_DENY".equalsIgnoreCase(behavior)) return Decision.DENY;
        }

        // 6. Check Remembered Decisions
        String key = modId + ":" + action + ":" + targetPath.toLowerCase();
        if (SettingsStorage.getData().rememberedPermissions.containsKey(key)) {
            String remembered = SettingsStorage.getData().rememberedPermissions.get(key);
            return "ALLOW".equalsIgnoreCase(remembered) ? Decision.ALLOW : Decision.DENY;
        }

        // 7. Global Default Behavior
        String globalDefault = SettingsStorage.getData().defaultModBehavior;
        if ("ALWAYS_ALLOW".equalsIgnoreCase(globalDefault)) return Decision.ALLOW;
        if ("ALWAYS_DENY".equalsIgnoreCase(globalDefault)) return Decision.DENY;

        return Decision.ASK;
    }
}
