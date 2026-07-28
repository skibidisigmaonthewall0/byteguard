# 🛡️ ByteGuard — Pre-Launch Security & Bytecode Threat Protection

![Version](https://img.shields.io/badge/Minecraft-1.21.11-brightgreen)
![Loader](https://img.shields.io/badge/Loader-Fabric-blue)
![Java](https://img.shields.io/badge/Java-21-orange)
![License](https://img.shields.io/badge/License-MIT-green)

**ByteGuard** is an advanced, enterprise-grade pre-launch security suite and bytecode analyzer designed to protect Minecraft players, server administrators, and modpack developers from malicious mods, Remote Access Trojans (RATs), token stealers, and supply-chain attacks.

Before your game loads, ByteGuard scans all `.jar` files in your `mods/` directory using deep ASM instruction flow analysis, integer stack simulation, string de-obfuscation, recursive Jar-in-Jar extraction, and native binary inspection — catching threats **before** any code can execute.

---

## ✨ Key Features

- 🔒 **Pre-Launch Gatekeeping**: Pauses Minecraft loading on launch to scan all mods. If a threat is detected, an interactive GUI allows you to inspect, allow, quarantine, or terminate the game.
- ⚡ **Scan Again Feature**: Instantly re-scan your `mods/` folder at any time to catch delay-run malicious payloads without restarting Minecraft.
- 📦 **Quarantine Engine**: Safely moves infected `.jar` files into a `.quarantine/` folder using an isolated background script, ensuring locked Windows files are cleaned after Minecraft closes.
- 🔍 **De-obfuscation & Stack Simulation**: Reconstructs XOR-encrypted strings, arithmetic delta (`I2C`) char building, concatenated `StringBuilder` fragments, and Base64 payloads.
- 👁️ **Unmasked Secrets Engine**: Displays 100% unmasked Discord webhooks, Discord bot tokens, Telegram tokens, Slack/Guilded tokens, GitHub PATs, and AWS keys so you know exactly where data was being sent.
- 🛡️ **JNI / Native Payload Parser**: Inspects embedded `.dll`, `.so`, and `.dylib` native binaries for malicious C/C++ imports (`URLDownloadToFile`, `WinHttpOpen`, `CreateProcess`, `WSAStartup`).
- 📁 **Recursive Jar-in-Jar (JiJ) Scanner**: Unpacks and scans embedded JARs inside `resources/` and `META-INF/jars/` (Fabric nested dependencies).
- 🏷️ **Code Signing Verification**: Verifies `META-INF/*.SF` and `*.RSA` certificates, flagging tampered or stripped signatures while trusting official Fabric project builds (`CN=Fabric`).
- 🧠 **0.0% False Positives on Core Mods**: Smart framework whitelisting for Fabric API (`fabric-*`), Mojang, Sponge, and Minecraft core code.

---

## 🦠 Malware Families Detected & Neutralized

ByteGuard comes pre-loaded with signatures and heuristics for major Minecraft malware campaigns:

| Family | Type | Vector & Indicators |
|---|---|---|
| **Fractureiser** | Supply-Chain Stealer | `dev/neko/`, `Updater.class`, `VMEscape`, `libWebGL64.jar`, `FriendlyByteBuf` spoofing |
| **WeedHack** | MaaS RAT | EtherHiding C2 (`cloudflare-eth.com`, `infura.io`, `eth_call`), webcam access, keylogging |
| **SilentNet** | RAT-as-a-Service | `silentnet.st` URLs, fake Krypton Client impersonation, DLL sideloading |
| **Skyrage** | Propagation Malware | `Updater.class` propagation loop, `vmd-gnu` Linux persistence service |
| **BleedingPipe** | RCE Exploit | Unsafe `ObjectInputStream` deserialization gadget chains |
| **Ghost Client RATs** | Fake Cheat RATs | Embedded RAT payloads in fake/leaked cheat clients |
| **Java RAT Frameworks** | Generic RAT Implants | Quasar RAT, JRAT, Adwind, DarkComet reverse shell handlers |

---

## 🎯 Threat Detection Matrix

| Category | Detection Capability |
|---|---|
| **Data Theft** | Minecraft session tokens (`getAccessToken`), Discord `Local Storage/leveldb`, Chrome/Firefox/Edge `Login Data` & `Cookies`, Crypto Wallets (`wallet.dat`, Metamask, Exodus) |
| **Surveillance** | `Robot.createScreenCapture()` + `ImageIO.write()` attack chains, `KeyboardFocusManager` keyloggers, `Clipboard` hijacking |
| **Execution Bypasses** | `Desktop.getDesktop().open()`, `System.getenv("WINDIR")` pathing, `Class.forName()` reflection, `MethodHandles.findVirtual()`, `sun.misc.Unsafe` |
| **Persistence** | Windows Startup folder, Registry Run keys (`HKCU\...\Run`), `schtasks`, Linux cron jobs, `~/.bashrc` |
| **VM Evasion** | Anti-analysis fingerprinting (`vmware`, `virtualbox`, `wireshark`, `procmon`, `ollydbg`, `x64dbg`) |

---

## ⚙️ Configuration & Customization

ByteGuard dynamically loads rules from `.minecraft/antirat-rules.json`. You can add custom JSON rules for new webhooks, domains, or string patterns without rebuilding the mod!

---

## 👨‍💻 Credits & License

- **Lead Developer**: MarkDev1337
- **AI Security Architecture**: Google Antigravity Security Suite
- **License**: MIT License
