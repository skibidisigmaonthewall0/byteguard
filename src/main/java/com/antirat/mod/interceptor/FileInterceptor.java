package com.antirat.mod.interceptor;

import com.antirat.mod.manager.PermissionManager;
import com.antirat.mod.metadata.ModMetadata;
import com.antirat.mod.util.Logger;

import java.io.File;

/**
 * Intercepts file system operations (read, write, delete, create).
 * Auto-denies access to sensitive token/account files without prompting.
 * 
 * TECHNICAL LIMITATION NOTE:
 * Mixing directly into java.io.FileInputStream/FileOutputStream inside Fabric triggers
 * MixinTargetAlreadyLoadedException because standard JDK I/O classes are loaded by the JVM bootstrap
 * classloader during Fabric initialization.
 * Runtime file protection is enforced via Minecraft/Fabric wrapper hooks and pre-launch ASM static scanning.
 */
public class FileInterceptor {

    private static final String[] SENSITIVE_TOKEN_FILES = {
        "launcher_accounts.json",
        "usercache.json",
        "usernamecache.json",
        "launcher_profiles.json",
        "discord/local storage",
        "level.dat"
    };

    /**
     * Intercepts a file access attempt.
     * Returns true if allowed, false if blocked.
     */
    public static boolean checkAccess(File file, String operation) {
        if (file == null) return true;

        String path = file.getAbsolutePath().replace('\\', '/').toLowerCase();
        String filename = file.getName().toLowerCase();
        String callerMod = ModMetadata.identifyCallerMod();

        // 1. Auto-Deny sensitive token/account files
        for (String sensitive : SENSITIVE_TOKEN_FILES) {
            if (filename.equals(sensitive) || path.contains(sensitive)) {
                Logger.logAction(callerMod, "FILE_" + operation, path, false);
                System.err.println("[AntiRAT BLOCK] Auto-denied access to sensitive file: " + path + " by mod: " + callerMod);
                return false;
            }
        }

        // 2. Check general .minecraft folder access
        if (path.contains(".minecraft")) {
            PermissionManager.Decision decision = PermissionManager.evaluatePermission(callerMod, "FILE_" + operation, path);

            if (decision == PermissionManager.Decision.ALLOW) {
                Logger.logAction(callerMod, "FILE_" + operation, path, true);
                return true;
            } else if (decision == PermissionManager.Decision.DENY) {
                Logger.logAction(callerMod, "FILE_" + operation, path, false);
                return false;
            } else {
                Logger.logAction(callerMod, "FILE_" + operation, path, false);
                System.out.println("[AntiRAT PROMPT] Suspicious file access: " + path + " (" + operation + ") by " + callerMod);
                return false;
            }
        }

        return true;
    }
}
