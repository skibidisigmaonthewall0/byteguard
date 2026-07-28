package com.antirat.mod.manager;

import com.antirat.mod.scanner.SecurityScanner;
import com.antirat.mod.util.Logger;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Manages pre-launch mod quarantine with a deferred Python cleanup script strategy.
 * Since JVM file locks prevent deletion while Minecraft is running, this drops a hidden
 * Python script to %TEMP% that waits for Minecraft to exit then deletes the mod from mods/.
 */
public class QuarantineManager {

    private static final List<SecurityScanner.SecurityReport> QUARANTINED_REPORTS = Collections.synchronizedList(new ArrayList<>());
    private static File quarantineDirectory;

    public static void init(File minecraftDir) {
        quarantineDirectory = new File(minecraftDir, "quarantine");
        if (!quarantineDirectory.exists()) {
            quarantineDirectory.mkdirs();
        }
    }

    public static void addQuarantinedReport(SecurityScanner.SecurityReport report) {
        QUARANTINED_REPORTS.add(report);
        Logger.log(report.metadata.getName(), "QUARANTINE", "Mod flagged during startup scan. Level: " + report.suspicionLevel.label, "FLAGGED");
    }

    public static List<SecurityScanner.SecurityReport> getQuarantinedReports() {
        return new ArrayList<>(QUARANTINED_REPORTS);
    }

    public static boolean hasQuarantinedMods() {
        return !QUARANTINED_REPORTS.isEmpty();
    }

    /**
     * Quarantine strategy:
     * 1. Copy the JAR from mods/ into .minecraft/quarantine/
     * 2. Write a hidden Python cleanup script to %TEMP%
     * 3. Launch the script as a hidden background process (windowless)
     * 4. Return — Minecraft then calls System.exit(0) so JVM releases file lock
     * 5. Python script waits for the Minecraft PID to die, then deletes the source mods/ JAR
     */
    public static boolean moveJarToQuarantine(File jarFile) {
        if (jarFile == null || !jarFile.exists() || !jarFile.isFile() || !jarFile.getName().endsWith(".jar")) {
            Logger.log("SYSTEM", "QUARANTINE", "Refused invalid file move target: " + jarFile, "FAILED");
            return false;
        }

        try {
            if (quarantineDirectory != null && !quarantineDirectory.exists()) {
                quarantineDirectory.mkdirs();
            }
            File targetFile = new File(quarantineDirectory, jarFile.getName());

            // Step 1: Copy JAR into quarantine folder first
            Files.copy(jarFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Logger.log(jarFile.getName(), "QUARANTINE_COPY", "Copied to quarantine: " + targetFile.getAbsolutePath(), "SUCCESS");

            // Step 2: Generate Python cleanup script in %TEMP%
            long currentPid = ProcessHandle.current().pid();
            String jarPath = jarFile.getAbsolutePath().replace("\\", "\\\\");
            String quarantinePath = targetFile.getAbsolutePath().replace("\\", "\\\\");

            String pyScript = "import os, time, sys\n\n" +
                "pid = " + currentPid + "\n" +
                "jar_path = r'" + jarFile.getAbsolutePath() + "'\n" +
                "quarantine_path = r'" + targetFile.getAbsolutePath() + "'\n\n" +
                "# Wait for Minecraft JVM process to fully exit\n" +
                "def pid_alive(p):\n" +
                "    try:\n" +
                "        import ctypes\n" +
                "        kernel32 = ctypes.windll.kernel32\n" +
                "        handle = kernel32.OpenProcess(1, False, int(p))\n" +
                "        if handle == 0:\n" +
                "            return False\n" +
                "        exit_code = ctypes.c_ulong()\n" +
                "        kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))\n" +
                "        kernel32.CloseHandle(handle)\n" +
                "        return exit_code.value == 259  # STILL_ACTIVE\n" +
                "    except:\n" +
                "        return False\n\n" +
                "print(f'[AntiRAT Cleanup] Waiting for Minecraft PID {pid} to exit...')\n" +
                "for i in range(60):\n" +
                "    if not pid_alive(pid):\n" +
                "        break\n" +
                "    time.sleep(1)\n\n" +
                "# Extra safety sleep to ensure JVM fully releases file handles\n" +
                "time.sleep(2)\n\n" +
                "# Delete source mod JAR from mods/\n" +
                "try:\n" +
                "    if os.path.exists(jar_path):\n" +
                "        os.remove(jar_path)\n" +
                "        print(f'[AntiRAT Cleanup] Deleted: {jar_path}')\n" +
                "    else:\n" +
                "        print(f'[AntiRAT Cleanup] Already gone: {jar_path}')\n" +
                "except Exception as e:\n" +
                "    print(f'[AntiRAT Cleanup] Error deleting: {e}')\n\n" +
                "# Self-destruct this script\n" +
                "try:\n" +
                "    os.remove(os.path.abspath(__file__))\n" +
                "except:\n" +
                "    pass\n";

            String tempDir = System.getenv("TEMP");
            if (tempDir == null || tempDir.isEmpty()) tempDir = System.getProperty("java.io.tmpdir");

            File pyFile = new File(tempDir, "antirat_cleanup_" + System.currentTimeMillis() + ".py");
            try (FileWriter fw = new FileWriter(pyFile)) {
                fw.write(pyScript);
            }

            Logger.log(jarFile.getName(), "QUARANTINE_SCRIPT", "Cleanup script written to: " + pyFile.getAbsolutePath(), "SUCCESS");

            // Step 3: Launch the Python cleanup script as a hidden background process
            ProcessBuilder pb = new ProcessBuilder(
                "pythonw.exe",          // pythonw = no console window on Windows
                pyFile.getAbsolutePath()
            );
            pb.redirectErrorStream(false);
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);

            try {
                pb.start();
                Logger.log(jarFile.getName(), "QUARANTINE_LAUNCH", "Hidden cleanup script launched: " + pyFile.getName(), "SUCCESS");
            } catch (Exception e) {
                // Fallback: try python instead of pythonw
                Logger.log(jarFile.getName(), "QUARANTINE_LAUNCH", "pythonw not found, trying python: " + e.getMessage(), "WARN");
                try {
                    ProcessBuilder pb2 = new ProcessBuilder("python", pyFile.getAbsolutePath());
                    pb2.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                    pb2.redirectError(ProcessBuilder.Redirect.DISCARD);
                    pb2.start();
                } catch (Exception ignored) {
                    Logger.log(jarFile.getName(), "QUARANTINE_LAUNCH", "Python unavailable, file will be removed on next Minecraft launch via quarantine manager.", "WARN");
                }
            }

            return true;

        } catch (Exception e) {
            Logger.log(jarFile != null ? jarFile.getName() : "unknown", "QUARANTINE_MOVE", "Critical error during quarantine: " + e.getMessage(), "ERROR");
            return false;
        }
    }
}
