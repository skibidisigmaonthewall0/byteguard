package com.antirat.mod.interceptor;

import com.antirat.mod.manager.PermissionManager;
import com.antirat.mod.metadata.ModMetadata;
import com.antirat.mod.util.Logger;

import java.util.List;

/**
 * Intercepts process execution attempts (cmd.exe, powershell, bash, curl, wget, nc, etc.).
 * 
 * TECHNICAL LIMITATION NOTE:
 * Mixing into java.lang.ProcessBuilder directly inside standard Fabric triggers
 * ClassInfo.addMixin UnsupportedOperationException because java.base core system classes
 * are protected in Java 21 KnotClassLoader. Process execution detection is enforced via
 * pre-launch ASM static bytecode scanning (SecurityScanner) and runtime command hooks.
 */
public class ProcessInterceptor {

    private static final String[] BLACKLISTED_COMMANDS = {
        "cmd.exe",
        "powershell",
        "bash",
        "sh",
        "curl",
        "wget",
        "nc",
        "netcat",
        ".exe",
        ".dll",
        ".bat",
        ".vbs",
        ".ps1"
    };

    public static boolean checkProcessExecution(List<String> command) {
        if (command == null || command.isEmpty()) return true;

        String fullCommand = String.join(" ", command).toLowerCase();
        String callerMod = ModMetadata.identifyCallerMod();

        boolean suspicious = false;
        for (String blacklisted : BLACKLISTED_COMMANDS) {
            if (fullCommand.contains(blacklisted)) {
                suspicious = true;
                break;
            }
        }

        if (suspicious) {
            PermissionManager.Decision decision = PermissionManager.evaluatePermission(callerMod, "EXECUTE_PROCESS", fullCommand);
            boolean allow = (decision == PermissionManager.Decision.ALLOW);

            Logger.logAction(callerMod, "PROCESS_EXEC", fullCommand, allow);
            if (!allow) {
                System.err.println("[AntiRAT BLOCK] Blocked process execution: \"" + fullCommand + "\" by mod: " + callerMod);
            }
            return allow;
        }

        return true;
    }
}
