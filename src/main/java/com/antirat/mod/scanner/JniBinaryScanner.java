package com.antirat.mod.scanner;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Embedded Native Binary Scanner (JNI / DLL / SO / DYLIB Trap).
 *
 * Malware authors attempt to bypass Java ASM bytecode analysis by embedding 
 * compiled C/C++ native binaries (.dll, .so, .dylib) inside resources/ or the JAR root 
 * and invoking them at runtime via System.load() / System.loadLibrary().
 *
 * JniBinaryScanner inspects all binary payloads for native import symbols,
 * Windows API functions, shell commands, and C2 networking imports:
 *  - URLDownloadToFileA/W, WinHttpOpen, InternetOpenUrlA/W
 *  - CreateProcessA/W, WinExec, system(), ShellExecuteA/W
 *  - WSAStartup, socket, connect, send, recv (C2 Sockets)
 *  - Keylogging: SetWindowsHookExA/W, GetAsyncKeyState
 *  - Injection: VirtualAlloc, WriteProcessMemory, CreateRemoteThread
 */
public class JniBinaryScanner {

    private static final List<String> NATIVE_SUSPICIOUS_IMPORTS = List.of(
        // Remote Payload Downloaders
        "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect",
        "WinHttpOpenRequest", "InternetOpenUrl", "InternetReadFile",
        "HttpOpenRequest", "URLOpenBlockingStream",

        // Native Process Execution & Shells
        "CreateProcess", "WinExec", "ShellExecute",
        "system", "popen", "execve", "execvp",

        // C2 Raw Network Sockets
        "WSAStartup", "WSASocket", "connect", "gethostbyname",
        "HttpSendRequest", "InternetConnect",

        // Memory Injection & Process Hijacking (RAT/Trojan)
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtMapViewOfSection", "QueueUserAPC",
        "OpenProcess", "RtlCreateUserThread",

        // Native Keylogging & Surveillance
        "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
        "GetWindowText", "BitBlt", "CreateCompatibleDC",

        // Shell strings in binary
        "cmd.exe", "powershell", "calc.exe", "/bin/sh", "/bin/bash"
    );

    public static class NativeScanResult {
        public boolean hasNativeBinary = false;
        public boolean isSuspicious = false;
        public final List<String> scannedLibraries = new ArrayList<>();
        public final List<String> detectedImports = new ArrayList<>();
        public int scoreAdded = 0;
    }

    public static NativeScanResult scanNativeLibraries(ZipFile zip) {
        NativeScanResult result = new NativeScanResult();

        var entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName().toLowerCase();

            boolean isNativeLib = name.endsWith(".dll") || name.endsWith(".so") ||
                                  name.endsWith(".dylib") || name.endsWith(".node") ||
                                  name.contains("nativ") || name.startsWith("nativ/");

            if (isNativeLib) {
                result.hasNativeBinary = true;
                result.scannedLibraries.add(entry.getName());

                try (InputStream is = zip.getInputStream(entry)) {
                    byte[] bytes = is.readAllBytes();
                    String rawBinary = new String(bytes, StandardCharsets.ISO_8859_1);

                    int matchCount = 0;
                    for (String imp : NATIVE_SUSPICIOUS_IMPORTS) {
                        if (rawBinary.contains(imp)) {
                            if (!result.detectedImports.contains(imp)) {
                                result.detectedImports.add(imp);
                            }
                            matchCount++;
                        }
                    }

                    if (matchCount > 0) {
                        result.isSuspicious = true;
                        result.scoreAdded += Math.min(matchCount * 30, 90);
                    } else {
                        // Even unflagged native binaries add moderate baseline scrutiny
                        result.scoreAdded += 25;
                    }
                } catch (Exception ignored) {}
            }
        }

        return result;
    }
}
