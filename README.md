# Anti-RAT Security Mod for Minecraft 1.21.11 (Fabric / Java 21)

A complete client-side Anti-RAT protection system for Minecraft 1.21.11 built on Fabric Loader 0.16.0+ and Java 21. Anti-RAT scans, detects, blocks, and reports malicious mod behavior before it can steal accounts, tokens, or execute arbitrary shell commands.

---

## Technical Architecture & Limitations

### 1. Pre-Launch Security Gate
- **Hook**: Implements `PreLaunchEntrypoint` provided by Fabric Loader.
- **Scanning**: Uses **ASM 9.7** bytecode analysis to inspect class files inside all `.jar` files in the `.minecraft/mods` directory before game initialization completes.
- **Quarantine**: Detects process execution APIs (`ProcessBuilder`, `Runtime.exec`), hardcoded Discord Webhooks, dynamic class loading (`URLClassLoader`, `Unsafe`), and sensitive account file references (`launcher_accounts.json`, `usercache.json`, `usernamecache.json`).
- **Limitation Note**: Fabric initializes `PreLaunchEntrypoint` prior to game window creation. However, JVM class loading for core libraries happens during bootstrap. For 100% bytecode interception prior to JVM bootstrap, pair this mod with a launcher bootstrap `-javaagent` argument.

### 2. Obfuscation Detection & Heuristics
- **Obfuscation Score (0–100)**: Calculated using string Shannon entropy, short class name ratio (`a/b/c`), synthetic method density, missing metadata (`fabric.mod.json`/`mcmod.info`), and suspicious reflection density.
- **Threshold**: Mods scoring over 50 or flagged with high-confidence RAT signatures are quarantined and trigger a startup `SecurityReportScreen`.

### 3. File System & Process Execution Interceptor
- **Auto-Deny Protection**: Automatically blocks access to `launcher_accounts.json`, `usercache.json`, and `usernamecache.json` without prompting.
- **Process Blocking**: Intercepts shell execution attempts (`cmd.exe`, `powershell`, `bash`, `sh`, `curl`, `wget`, `nc`, `netcat`, `.exe`, `.dll`, `.bat`).
- **Interactive Prompts**: Prompts the user with `PermissionPromptScreen` for flagged `.minecraft` folder accesses.

### 4. ClickGUI & Controls
- **Default Keybind**: `Right Shift` (configurable in Controls menu).
- **Tabs**:
  - `SETTINGS`: Toggle Safe Mode, Emergency Kill Switch, Default Mod Behavior.
  - `WHITELIST`: View/Manage allowed mods.
  - `BLACKLIST`: View/Manage denied mods.
  - `SCAN_RESULTS`: Review pre-launch quarantine reports.
  - `LOGS`: Live log viewer for allowed/denied actions.
  - `IMPORT_EXPORT`: Export/Import permissions and settings as JSON.

---

## Log Format

All events are logged to `.minecraft/anti-rat-logs.txt`:
```
[timestamp] [MOD_NAME] [ACTION_TYPE] [FILE/PATH/COMMAND] [ALLOWED/DENIED]
```
Example:
```
[2026-07-28 13:10:00] [MaliciousMod] [FILE_READ] [C:/Users/.../launcher_accounts.json] [DENIED]
[2026-07-28 13:10:05] [MaliciousMod] [PROCESS_EXEC] [powershell -nop -c ...] [DENIED]
```

---

## Blocked Mod Response & Quarantine

When a malicious mod is detected:
1. Minecraft startup is paused, and `SecurityReportScreen` displays the full report (mod name, JAR filename, suspicion level, capabilities, obfuscation score, reasons).
2. The user can choose:
   - **Allow Once**
   - **Always Allow**
   - **Quarantine** (safely moves the JAR file to `.minecraft/quarantine/`)
   - **Open Folder**
   - **Close Minecraft**

> **Safety Guarantee**: Anti-RAT never deletes your `.minecraft` folder, saves, screenshots, or resource packs. All file operations are strictly scoped and non-destructive.

---

## Build & Installation

1. Prerequisites: **Java 21 SDK**, **Gradle**.
2. Build command:
   ```bash
   ./gradlew build
   ```
3. Copy the compiled JAR from `build/libs/anti-rat-1.0.0.jar` into your Minecraft `.minecraft/mods` folder.
