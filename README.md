# 🛡️ ByteGuard — Pre-Launch Security & Bytecode Threat Protection

![Version](https://img.shields.io/badge/Minecraft-1.21.11-brightgreen)
![Loader](https://img.shields.io/badge/Loader-Fabric-blue)
![Java](https://img.shields.io/badge/Java-21-orange)
![License](https://img.shields.io/badge/License-MIT-green)

**ByteGuard** is an open-source, enterprise-grade pre-launch security suite and bytecode analyzer designed to protect Minecraft players, server administrators, and modpack developers from malicious mods, Remote Access Trojans (RATs), token stealers, and supply-chain attacks.

Before your game loads, ByteGuard scans all `.jar` files in your `mods/` directory using deep ASM instruction flow analysis, integer stack simulation, string de-obfuscation, recursive Jar-in-Jar extraction, and native binary inspection — catching threats **before** any code can execute.

---

## Technical Architecture & Capabilities

### 1. Pre-Launch Security Gate
- **Hook**: Implements `PreLaunchEntrypoint` provided by Fabric Loader.
- **Scanning**: Uses **ASM 9.7** bytecode analysis to inspect class files inside all `.jar` files in the `.minecraft/mods` directory before game initialization completes.
- **Quarantine Engine**: Detects process execution APIs (`ProcessBuilder`, `Runtime.exec`), hardcoded Discord Webhooks, dynamic class loading (`URLClassLoader`, `Unsafe`), and sensitive account file references (`launcher_accounts.json`, `usercache.json`, `usernamecache.json`).

### 2. Obfuscation Detection & Heuristics
- **Obfuscation Score (0–100)**: Calculated using string Shannon entropy, short class name ratio (`a/b/c`), synthetic method density, missing metadata (`fabric.mod.json`/`mcmod.info`), and suspicious reflection density.
- **Threshold**: Mods scoring over 50 or flagged with high-confidence RAT signatures trigger the pre-launch security suite GUI.

### 3. File System & Process Execution Interceptor
- **Auto-Deny Protection**: Automatically blocks access to `launcher_accounts.json`, `usercache.json`, and `usernamecache.json` without prompting.
- **Process Blocking**: Intercepts shell execution attempts (`cmd.exe`, `powershell`, `bash`, `sh`, `curl`, `wget`, `nc`, `netcat`, `.exe`, `.dll`, `.bat`).

---

## 🦠 Malware Families Neutralized

| Family | Vector & Indicators |
|---|---|
| **Fractureiser** | `dev/neko/`, `Updater.class`, `VMEscape`, `libWebGL64.jar`, `FriendlyByteBuf` spoofing |
| **WeedHack** | EtherHiding C2 (`cloudflare-eth.com`, `infura.io`, `eth_call`), webcam access, keylogging |
| **SilentNet** | `silentnet.st` URLs, fake Krypton Client impersonation, DLL sideloading |
| **Skyrage** | `Updater.class` propagation loop, `vmd-gnu` Linux persistence service |
| **BleedingPipe** | Unsafe `ObjectInputStream` deserialization gadget chains |
| **Ghost Client RATs** | Embedded RAT payloads in fake/leaked cheat clients |
| **Java RAT Frameworks** | Quasar RAT, JRAT, Adwind, DarkComet reverse shell handlers |

---

## 📦 Build & Installation

1. Prerequisites: **Java 21 SDK**, **Gradle**.
2. Build command:
   ```bash
   build.bat
   ```
3. Copy the compiled JAR from `build/libs/byteguard-1.0.0.jar` into your Minecraft `.minecraft/mods` folder.

---

## 👨‍💻 License

Distributed under the **MIT License**. Copyright (c) 2026 MarkDev1337.
