#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NECROBIN — digital autopsy for malware binaries
================================================
Static-only triage for PE / ELF / Mach-O / DEX / APK / raw blobs.

NEVER executes the sample. Reads bytes from disk and optionally shells out
to read-only helpers (file, strings, readelf, objdump, yara, unzip, ssdeep).

Python 3.7+ standard library only. Optional extras (file, yara, ssdeep, curl) are auto-detected.

  python3 necrobin.py sample.bin
  python3 necrobin.py -i sample.bin          # interactive menu
  python3 necrobin.py --compare a.bin b.bin
  python3 necrobin.py --report sample.bin -o autopsy.txt
"""

from __future__ import print_function

import argparse
import datetime
import hashlib
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from collections import Counter, OrderedDict

VERSION = "1.2.0"
NAME = "NECROBIN"
TAGLINE = "digital autopsy for the undead code"

# ---------------------------------------------------------------------------
# Terminal color / UI
# ---------------------------------------------------------------------------

def _supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


COLOR = _supports_color()


class C:
    """ANSI palette — morgue / necrotic theme."""
    reset = "\033[0m" if COLOR else ""
    bold = "\033[1m" if COLOR else ""
    dim = "\033[2m" if COLOR else ""
    italic = "\033[3m" if COLOR else ""
    under = "\033[4m" if COLOR else ""
    blink = "\033[5m" if COLOR else ""
    rev = "\033[7m" if COLOR else ""

    # core
    bone = "\033[38;5;253m" if COLOR else ""
    ash = "\033[38;5;245m" if COLOR else ""
    slate = "\033[38;5;240m" if COLOR else ""
    blood = "\033[38;5;160m" if COLOR else ""
    rust = "\033[38;5;166m" if COLOR else ""
    amber = "\033[38;5;214m" if COLOR else ""
    gold = "\033[38;5;178m" if COLOR else ""
    lime = "\033[38;5;148m" if COLOR else ""
    moss = "\033[38;5;71m" if COLOR else ""
    teal = "\033[38;5;37m" if COLOR else ""
    cyan = "\033[38;5;51m" if COLOR else ""
    ice = "\033[38;5;117m" if COLOR else ""
    violet = "\033[38;5;141m" if COLOR else ""
    grape = "\033[38;5;99m" if COLOR else ""
    rose = "\033[38;5;204m" if COLOR else ""
    white = "\033[38;5;255m" if COLOR else ""
    red = "\033[38;5;196m" if COLOR else ""
    green = "\033[38;5;82m" if COLOR else ""

    bg_blood = "\033[48;5;52m" if COLOR else ""
    bg_tomb = "\033[48;5;235m" if COLOR else ""
    bg_gold = "\033[48;5;94m" if COLOR else ""
    bg_void = "\033[48;5;16m" if COLOR else ""

    @staticmethod
    def wrap(code, text):
        return "%s%s%s" % (code, text, C.reset)


def cprint(*args, **kwargs):
    end = kwargs.get("end", "\n")
    sep = kwargs.get("sep", " ")
    sys.stdout.write(sep.join(str(a) for a in args) + end)
    sys.stdout.flush()


def rule(ch="─", n=78, color=None):
    color = color or C.slate
    cprint(color + ch * n + C.reset)


def banner():
    art = r"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   ███╗   ██╗███████╗ ██████╗██████╗  ██████╗ ██████╗ ██╗███╗   ██╗║
    ║   ████╗  ██║██╔════╝██╔════╝██╔══██╗██╔═══██╗██╔══██╗██║████╗  ██║║
    ║   ██╔██╗ ██║█████╗  ██║     ██████╔╝██║   ██║██████╔╝██║██╔██╗ ██║║
    ║   ██║╚██╗██║██╔══╝  ██║     ██╔══██╗██║   ██║██╔══██╗██║██║╚██╗██║║
    ║   ██║ ╚████║███████╗╚██████╗██║  ██║╚██████╔╝██████╔╝██║██║ ╚████║║
    ║   ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝"""
    # narrower fallback for tight terminals
    small = r"""
    ┌─────────────────────────────────────────┐
    │  N E C R O B I N   v%s              │
    │  digital autopsy for the undead code    │
    └─────────────────────────────────────────┘""" % VERSION
    cols = 80
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        pass
    skull = r"""
              ______
           .-'      '-.
          /            \
         |              |
         |,  .-.  .-.  ,|
         | )(_o/  \o_)( |
         |/     /\     \|
         (_     ^^     _)
          \__|IIIIII|__/
           | \IIIIII/ |
           \          /
            `--------`
    """
    cprint(C.blood + C.bold + (art if cols >= 78 else small) + C.reset)
    if cols >= 50:
        cprint(C.slate + skull + C.reset)
    cprint(C.ash + "    static-only · never executes the sample · v%s" % VERSION + C.reset)
    cprint(C.slate + "    " + TAGLINE + C.reset)
    print()


def section(title, glyph="✝"):
    print()
    cprint(C.gold + C.bold + "  %s  %s" % (glyph, title.upper()) + C.reset)
    rule("─", 78, C.slate)


def kv(key, value, key_w=22, vcolor=None):
    vcolor = vcolor or C.bone
    cprint("  %s%-*s%s %s%s%s" % (C.ash, key_w, key, C.reset, vcolor, value, C.reset))


def flag(level, text):
    colors = {
        "info": C.ice,
        "ok": C.lime,
        "low": C.moss,
        "med": C.amber,
        "high": C.rust,
        "crit": C.red + C.bold,
        "note": C.violet,
    }
    tags = {
        "info": "[INFO]",
        "ok": "[ OK ]",
        "low": "[LOW ]",
        "med": "[MED ]",
        "high": "[HIGH]",
        "crit": "[CRIT]",
        "note": "[NOTE]",
    }
    col = colors.get(level, C.bone)
    tag = tags.get(level, "[ -- ]")
    cprint("  %s%s%s %s" % (col, tag, C.reset, text))


def entropy_bar(ent, width=36):
    """Colored bar for entropy 0..8."""
    ent = max(0.0, min(8.0, float(ent)))
    filled = int(round((ent / 8.0) * width))
    if ent < 3.0:
        col = C.lime
    elif ent < 6.0:
        col = C.gold
    elif ent < 7.2:
        col = C.amber
    else:
        col = C.red
    bar = "█" * filled + C.slate + "░" * (width - filled)
    return "%s%s%s %s%0.3f%s" % (col, bar, C.reset, col, ent, C.reset)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def which(cmd):
    return shutil.which(cmd)


def run_cmd(argv, timeout=20, input_bytes=None):
    try:
        p = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            input=input_bytes,
        )
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return p.returncode, out, err
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0 or unit == "GB":
            if unit == "B":
                return "%d B" % int(n)
            return "%.2f %s" % (n, unit)
        n /= 1024.0


def safe_ascii(b, fallback="."):
    if isinstance(b, int):
        b = bytes([b])
    out = []
    for x in b:
        out.append(chr(x) if 32 <= x < 127 else fallback)
    return "".join(out)


def read_file(path, max_bytes=None):
    with open(path, "rb") as f:
        if max_bytes is None:
            return f.read()
        return f.read(max_bytes)



def utc_dt(ts=None):
    """timezone-aware UTC datetime, compatible with older Python."""
    tz = datetime.timezone.utc
    if ts is None:
        return datetime.datetime.now(tz)
    try:
        return datetime.datetime.fromtimestamp(int(ts), tz)
    except Exception:
        return None

def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = float(len(data))
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log(p, 2)
    return ent


def windowed_entropy(data, win=256, step=None):
    if step is None:
        step = max(64, win // 2)
    if len(data) < win:
        return [(0, shannon_entropy(data))]
    out = []
    i = 0
    while i < len(data):
        chunk = data[i:i + win]
        out.append((i, shannon_entropy(chunk)))
        i += step
    return out


def ascii_heatmap(windows, width=64):
    """Map window entropy to a single-line heatmap."""
    if not windows:
        return ""
    chars = " ▁▂▃▄▅▆▇█"
    # downsample to width
    n = len(windows)
    buckets = []
    for i in range(width):
        a = int(i * n / width)
        b = int((i + 1) * n / width)
        sl = windows[a:max(b, a + 1)]
        avg = sum(w[1] for w in sl) / float(len(sl))
        buckets.append(avg)
    line = []
    for e in buckets:
        idx = int(round((e / 8.0) * (len(chars) - 1)))
        idx = max(0, min(len(chars) - 1, idx))
        if e >= 7.2:
            col = C.red
        elif e >= 6.0:
            col = C.amber
        elif e >= 4.0:
            col = C.gold
        else:
            col = C.moss
        line.append(col + chars[idx])
    return "".join(line) + C.reset


# ---------------------------------------------------------------------------
# File identification
# ---------------------------------------------------------------------------

MAGIC_TABLE = [
    (b"MZ", "PE/DOS MZ stub (possible Windows PE)"),
    (b"\x7fELF", "ELF executable/object"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit BE"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit LE"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit BE"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit LE"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat / Java class cafe babe"),
    (b"dex\n", "Android DEX"),
    (b"PK\x03\x04", "ZIP / APK / JAR / DOCX / package"),
    (b"%PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound (DOC/XLS/PPT/MSI)"),
    (b"\x7f\x45\x4c\x46", "ELF"),
    (b"\x23\x21", "shebang script"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\xed\xab\xee\xdb", "RPM"),
    (b"!<arch>", "UNIX ar / .deb data"),
    (b"\x00asm", "WebAssembly"),
    (b"{\\rtf", "RTF"),
]


def identify_magic(data):
    hits = []
    for mag, desc in MAGIC_TABLE:
        if data.startswith(mag):
            hits.append(("header", desc))
    # cafe babe distinction
    if data[:4] == b"\xca\xfe\xba\xbe" and len(data) > 8:
        nfat = struct.unpack(">I", data[4:8])[0]
        if nfat < 16:
            hits.append(("header", "Mach-O universal (fat) binary, %d arch(s)" % nfat))
        else:
            hits.append(("header", "likely Java .class (cafe babe)"))
    return hits


def file_cmd(path):
    if not which("file"):
        return None
    rc, out, _ = run_cmd(["file", "-b", path])
    return out.strip() if rc == 0 else None


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def all_hashes(data):
    h = OrderedDict()
    h["md5"] = hashlib.md5(data).hexdigest()
    h["sha1"] = hashlib.sha1(data).hexdigest()
    h["sha256"] = hashlib.sha256(data).hexdigest()
    h["sha512"] = hashlib.sha512(data).hexdigest()
    h["crc32"] = "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)
    if hasattr(hashlib, "blake2b"):
        h["blake2b"] = hashlib.blake2b(data, digest_size=32).hexdigest()
    if hasattr(hashlib, "sha3_256"):
        h["sha3_256"] = hashlib.sha3_256(data).hexdigest()
    return h


def ssdeep_hash(path):
    for cmd in ("ssdeep", "ssdeep-hash"):
        if which(cmd):
            rc, out, _ = run_cmd([cmd, "-b", path])
            if rc == 0:
                # ssdeep -b : hash,filename
                line = out.strip().splitlines()[-1]
                parts = line.split(",")
                if parts:
                    return parts[0].strip()
    return None


# ---------------------------------------------------------------------------
# PE parser (pure python, malware-tolerant)
# ---------------------------------------------------------------------------

MACHINE = {
    0x0: "UNKNOWN", 0x14C: "I386", 0x8664: "AMD64", 0x1C0: "ARM",
    0xAA64: "ARM64", 0x1C4: "ARMNT", 0x166: "MIPS", 0x266: "MIPS16",
    0x366: "MIPSFPU", 0x466: "MIPSFPU16", 0x184: "ALPHA", 0x1F0: "POWERPC",
    0x1F1: "POWERPCFP", 0x200: "IA64", 0x14D: "I860", 0x169: "WCEMIPSV2",
    0x1A2: "SH3", 0x1A3: "SH3DSP", 0x1A6: "SH4", 0x1A8: "SH5",
    0x520: "TRICORE", 0xCEF: "CEF", 0xEBC: "EBC", 0x9041: "M32R",
    0xC0EE: "CEE", 0xA641: "ARM64EC",
}

PE_CHARS = [
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0010, "AGGRESSIVE_WS_TRIM"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0080, "BYTES_REVERSED_LO"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
    (0x8000, "BYTES_REVERSED_HI"),
]

SEC_CHARS = [
    (0x00000020, "CODE"),
    (0x00000040, "INITIALIZED_DATA"),
    (0x00000080, "UNINITIALIZED_DATA"),
    (0x02000000, "DISCARDABLE"),
    (0x10000000, "SHARED"),
    (0x20000000, "EXECUTE"),
    (0x40000000, "READ"),
    (0x80000000, "WRITE"),
]

DLL_CHARS = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]

SUBSYSTEM = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
    5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI", 10: "EFI_APP",
    11: "EFI_BOOT", 12: "EFI_RUNTIME", 13: "EFI_ROM", 14: "XBOX",
    16: "WINDOWS_BOOT",
}

SUSPICIOUS_SECTIONS = {
    "UPX0", "UPX1", "UPX2", ".UPX", "MPRESS1", "MPRESS2",
    ".aspack", ".adata", "PEPACK1", ".nsp0", ".nsp1",
    "Themida", ".themida", "VMprotect", ".vmp0", ".vmp1",
    ".enigma1", ".enigma2", "MEW", ".pec1", ".pec2",
    "BitArts", ".yP", ".ccg", "kkrunchy",
}

SUSPICIOUS_IMPORTS = {
    # process / injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtMapViewOfSection",
    "OpenProcess", "OpenThread", "SuspendThread", "ResumeThread",
    # persistence / services
    "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
    "CreateService", "StartService", "ChangeServiceConfig",
    # networking
    "InternetOpen", "InternetConnect", "InternetOpenUrl", "HttpSendRequest",
    "URLDownloadToFile", "WinHttpOpen", "WSAStartup", "socket", "connect",
    "send", "recv", "InternetReadFile", "HttpOpenRequest",
    # crypto / steal
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "BCryptEncrypt",
    "CredEnumerate", "CryptUnprotectData",
    # anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
    "FindWindow", "GetForegroundWindow",
    # file / drop
    "WinExec", "ShellExecute", "CreateProcess", "CreateProcessAsUser",
    "NtCreateFile", "WriteFile", "CopyFile", "MoveFile",
    # hooking
    "SetWindowsHookEx", "SetWinEventHook",
    # privilege
    "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
}


def _u16(data, off):
    if off + 2 > len(data):
        raise ValueError("short read u16 @ %d" % off)
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    if off + 4 > len(data):
        raise ValueError("short read u32 @ %d" % off)
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    if off + 8 > len(data):
        raise ValueError("short read u64 @ %d" % off)
    return struct.unpack_from("<Q", data, off)[0]


def parse_pe(data):
    info = {"valid": False, "warnings": []}
    if len(data) < 64 or data[:2] != b"MZ":
        return info
    try:
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew < 0x40 or e_lfanew + 4 > len(data):
            info["warnings"].append("e_lfanew out of range: 0x%X" % e_lfanew)
            return info
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            info["warnings"].append("MZ present but PE signature missing at 0x%X" % e_lfanew)
            return info
        coff = e_lfanew + 4
        machine = _u16(data, coff)
        nsec = _u16(data, coff + 2)
        ts = _u32(data, coff + 4)
        opt_size = _u16(data, coff + 16)
        chars = _u16(data, coff + 18)
        opt = coff + 20
        if opt + opt_size > len(data):
            info["warnings"].append("optional header truncated")
            return info
        magic = _u16(data, opt)
        pe32plus = magic == 0x20B
        pe32 = magic == 0x10B
        if not (pe32 or pe32plus):
            info["warnings"].append("unknown optional magic 0x%X" % magic)
        # fields
        if pe32plus:
            entry = _u32(data, opt + 16)
            image_base = _u64(data, opt + 24)
            section_align = _u32(data, opt + 32)
            file_align = _u32(data, opt + 36)
            os_maj, os_min = _u16(data, opt + 40), _u16(data, opt + 42)
            subsys = _u16(data, opt + 68)
            dll_chars = _u16(data, opt + 70)
            size_image = _u32(data, opt + 56)
            size_headers = _u32(data, opt + 60)
            dd_count = _u32(data, opt + 108) if opt + 112 <= len(data) else 0
            dd_off = opt + 112
        else:
            entry = _u32(data, opt + 16)
            image_base = _u32(data, opt + 28)
            section_align = _u32(data, opt + 32)
            file_align = _u32(data, opt + 36)
            os_maj, os_min = _u16(data, opt + 40), _u16(data, opt + 42)
            subsys = _u16(data, opt + 68)
            dll_chars = _u16(data, opt + 70)
            size_image = _u32(data, opt + 56)
            size_headers = _u32(data, opt + 60)
            dd_count = _u32(data, opt + 92) if opt + 96 <= len(data) else 0
            dd_off = opt + 96

        dirs = []
        for i in range(min(int(dd_count), 16)):
            o = dd_off + i * 8
            if o + 8 > len(data):
                break
            dirs.append((_u32(data, o), _u32(data, o + 4)))

        # sections
        sec_off = opt + opt_size
        sections = []
        last_raw_end = 0
        for i in range(min(int(nsec), 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                info["warnings"].append("section table truncated at #%d" % i)
                break
            name = data[o:o + 8].split(b"\x00", 1)[0]
            try:
                name_s = name.decode("ascii", "replace")
            except Exception:
                name_s = repr(name)
            vsize = _u32(data, o + 8)
            vaddr = _u32(data, o + 12)
            raw_size = _u32(data, o + 16)
            raw_ptr = _u32(data, o + 20)
            schars = _u32(data, o + 36)
            blob = b""
            if raw_ptr and raw_size and raw_ptr < len(data):
                blob = data[raw_ptr:raw_ptr + min(raw_size, len(data) - raw_ptr)]
            ent = shannon_entropy(blob) if blob else 0.0
            flags = [n for bit, n in SEC_CHARS if schars & bit]
            sections.append({
                "name": name_s,
                "vsize": vsize,
                "vaddr": vaddr,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "chars": schars,
                "flags": flags,
                "entropy": ent,
            })
            last_raw_end = max(last_raw_end, raw_ptr + raw_size)

        overlay = 0
        if last_raw_end and last_raw_end < len(data):
            overlay = len(data) - last_raw_end

        try:
            dt = utc_dt(ts)
            compiled = dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "unrepresentable"
        except Exception:
            compiled = "unrepresentable"

        # compile-time sanity
        year = 1970
        try:
            year = (utc_dt(ts).year if utc_dt(ts) else 1970)
        except Exception:
            pass

        imports = parse_pe_imports(data, sections, dirs, pe32plus)
        exports = parse_pe_exports(data, sections, dirs)

        info.update({
            "valid": True,
            "e_lfanew": e_lfanew,
            "machine": MACHINE.get(machine, "0x%X" % machine),
            "machine_raw": machine,
            "sections_n": nsec,
            "timestamp": ts,
            "compiled": compiled,
            "compile_year": year,
            "characteristics": chars,
            "char_flags": [n for bit, n in PE_CHARS if chars & bit],
            "pe32plus": pe32plus,
            "entry_rva": entry,
            "image_base": image_base,
            "section_align": section_align,
            "file_align": file_align,
            "os": "%d.%d" % (os_maj, os_min),
            "subsystem": SUBSYSTEM.get(subsys, str(subsys)),
            "dll_chars": dll_chars,
            "dll_flags": [n for bit, n in DLL_CHARS if dll_chars & bit],
            "size_image": size_image,
            "size_headers": size_headers,
            "data_dirs": dirs,
            "sections": sections,
            "overlay": overlay,
            "imports": imports,
            "exports": exports,
            "is_dll": bool(chars & 0x2000),
            "cert_dir": dirs[4] if len(dirs) > 4 else (0, 0),
            "com_dir": dirs[14] if len(dirs) > 14 else (0, 0),
        })
        info["has_signature"] = bool(info["cert_dir"][0] and info["cert_dir"][1])
        info["is_dotnet"] = bool(info["com_dir"][0] and info["com_dir"][1])
        try:
            info["rich"] = parse_rich_header(data, e_lfanew)
        except Exception:
            info["rich"] = {"present": False}
    except Exception as e:
        info["warnings"].append("PE parse error: %s" % e)
    return info


def rva_to_off(rva, sections):
    for s in sections:
        vs = max(s["vsize"], s["raw_size"])
        if s["vaddr"] <= rva < s["vaddr"] + vs:
            return s["raw_ptr"] + (rva - s["vaddr"])
    return None


def parse_pe_imports(data, sections, dirs, pe32plus):
    result = []
    if len(dirs) < 2 or dirs[1][0] == 0:
        return result
    off = rva_to_off(dirs[1][0], sections)
    if off is None:
        return result
    ptr_size = 8 if pe32plus else 4
    # IMAGE_IMPORT_DESCRIPTOR is 20 bytes
    for i in range(256):
        o = off + i * 20
        if o + 20 > len(data):
            break
        ilt = _u32(data, o)
        name_rva = _u32(data, o + 12)
        iat = _u32(data, o + 16)
        if ilt == 0 and name_rva == 0 and iat == 0:
            break
        name_off = rva_to_off(name_rva, sections) if name_rva else None
        dll = ""
        if name_off is not None and name_off < len(data):
            end = data.find(b"\x00", name_off, name_off + 256)
            if end == -1:
                end = name_off + 32
            dll = data[name_off:end].decode("ascii", "replace")
        funcs = []
        thunk_rva = ilt or iat
        thunk_off = rva_to_off(thunk_rva, sections) if thunk_rva else None
        if thunk_off is not None:
            for j in range(512):
                to = thunk_off + j * ptr_size
                if to + ptr_size > len(data):
                    break
                if pe32plus:
                    val = _u64(data, to)
                    ordinal_flag = val & (1 << 63)
                    hint_rva = val & 0x7FFFFFFFFFFFFFFF
                else:
                    val = _u32(data, to)
                    ordinal_flag = val & 0x80000000
                    hint_rva = val & 0x7FFFFFFF
                if val == 0:
                    break
                if ordinal_flag:
                    funcs.append("#%d" % (hint_rva & 0xFFFF))
                else:
                    no = rva_to_off(hint_rva, sections)
                    if no is not None and no + 2 < len(data):
                        nend = data.find(b"\x00", no + 2, no + 2 + 256)
                        if nend == -1:
                            nend = no + 2 + 32
                        fname = data[no + 2:nend].decode("ascii", "replace")
                        funcs.append(fname)
                    else:
                        funcs.append("rva:0x%X" % hint_rva)
        result.append({"dll": dll, "funcs": funcs})
    return result


def parse_pe_exports(data, sections, dirs):
    names = []
    if len(dirs) < 1 or dirs[0][0] == 0:
        return names
    off = rva_to_off(dirs[0][0], sections)
    if off is None or off + 40 > len(data):
        return names
    try:
        nnames = _u32(data, off + 24)
        names_rva = _u32(data, off + 32)
        noff = rva_to_off(names_rva, sections)
        if noff is None:
            return names
        for i in range(min(int(nnames), 512)):
            nrva = _u32(data, noff + i * 4)
            npos = rva_to_off(nrva, sections)
            if npos is None:
                continue
            end = data.find(b"\x00", npos, npos + 256)
            if end == -1:
                end = npos + 32
            names.append(data[npos:end].decode("ascii", "replace"))
    except Exception:
        pass
    return names


def pe_imphash(imports):
    """pestudio/pefile-compatible-ish imphash (lowercased name.func joined)."""
    parts = []
    for imp in imports:
        dll = (imp.get("dll") or "").lower()
        if dll.endswith(".dll"):
            dll = dll[:-4]
        for f in imp.get("funcs") or []:
            parts.append("%s.%s" % (dll, f.lower()))
    if not parts:
        return None
    blob = ",".join(parts).encode("ascii", "replace")
    return hashlib.md5(blob).hexdigest()


# ---------------------------------------------------------------------------
# ELF parser
# ---------------------------------------------------------------------------

ELF_CLASS = {1: "ELF32", 2: "ELF64"}
ELF_DATA = {1: "LITTLE", 2: "BIG"}
ELF_TYPE = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN (pie/shared)", 4: "CORE"}
ELF_OSABI = {
    0: "SYSV", 1: "HPUX", 2: "NETBSD", 3: "LINUX", 6: "SOLARIS",
    9: "FREEBSD", 12: "OPENBSD", 13: "OPENVMS", 14: "NSK",
}
ELF_MACHINE = {
    0: "NONE", 3: "386", 8: "MIPS", 20: "PPC", 21: "PPC64",
    40: "ARM", 62: "X86_64", 183: "AARCH64", 243: "RISCV",
    42: "SH", 2: "SPARC", 15: "FIREPATH",
}


def parse_elf(data):
    info = {"valid": False, "warnings": []}
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return info
    try:
        ei_class = data[4]
        ei_data = data[5]
        ei_ver = data[6]
        ei_osabi = data[7]
        endian = "<" if ei_data == 1 else ">"
        if ei_class == 1:
            eh = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
                e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = (
                    eh[0], eh[1], eh[2], eh[3], eh[4], eh[5], eh[6],
                    eh[7], eh[8], eh[9], eh[10], eh[11], eh[12]
                )
        elif ei_class == 2:
            if len(data) < 64:
                info["warnings"].append("ELF64 header truncated")
                return info
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_version = struct.unpack_from(endian + "I", data, 20)[0]
            e_entry, e_phoff, e_shoff = struct.unpack_from(endian + "QQQ", data, 24)
            e_flags = struct.unpack_from(endian + "I", data, 48)[0]
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(endian + "HHHHHH", data, 52)
        else:
            info["warnings"].append("unknown EI_CLASS %d" % ei_class)
            return info

        sections = []
        shstr = b""
        # section header string table
        if e_shoff and e_shnum and e_shentsize and e_shstrndx < e_shnum:
            shtbl = e_shoff + e_shstrndx * e_shentsize
            if ei_class == 1 and shtbl + 40 <= len(data):
                sh_offset = struct.unpack_from(endian + "I", data, shtbl + 16)[0]
                sh_size = struct.unpack_from(endian + "I", data, shtbl + 20)[0]
            elif ei_class == 2 and shtbl + 64 <= len(data):
                sh_offset = struct.unpack_from(endian + "Q", data, shtbl + 24)[0]
                sh_size = struct.unpack_from(endian + "Q", data, shtbl + 32)[0]
            else:
                sh_offset = sh_size = 0
            if sh_offset and sh_size and sh_offset + sh_size <= len(data):
                shstr = data[sh_offset:sh_offset + sh_size]

        def sec_name(idx):
            if not shstr or idx >= len(shstr):
                return ""
            end = shstr.find(b"\x00", idx)
            if end == -1:
                end = min(idx + 32, len(shstr))
            return shstr[idx:end].decode("ascii", "replace")

        needed = []
        interp = None
        dynsym_names = []

        if e_shoff and e_shnum and e_shentsize:
            for i in range(min(int(e_shnum), 256)):
                o = e_shoff + i * e_shentsize
                if o + e_shentsize > len(data):
                    break
                if ei_class == 1:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                        struct.unpack_from(endian + "IIIIII", data, o)
                else:
                    sh_name, sh_type = struct.unpack_from(endian + "II", data, o)
                    sh_flags, sh_addr, sh_offset, sh_size = \
                        struct.unpack_from(endian + "QQQQ", data, o + 8)
                nm = sec_name(sh_name)
                blob = b""
                if sh_offset and sh_size and sh_offset < len(data):
                    blob = data[sh_offset:sh_offset + min(int(sh_size), len(data) - sh_offset)]
                sections.append({
                    "name": nm,
                    "type": sh_type,
                    "addr": sh_addr,
                    "offset": sh_offset,
                    "size": sh_size,
                    "entropy": shannon_entropy(blob) if blob else 0.0,
                })
                if nm == ".interp" and blob:
                    interp = blob.split(b"\x00", 1)[0].decode("ascii", "replace")
                if nm == ".dynstr" and blob:
                    # harvest DT_NEEDED later via strings of dynstr
                    pass

        # PT_INTERP / PT_DYNAMIC from program headers
        if e_phoff and e_phnum and e_phentsize:
            for i in range(min(int(e_phnum), 128)):
                o = e_phoff + i * e_phentsize
                if o + e_phentsize > len(data):
                    break
                if ei_class == 1:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                        struct.unpack_from(endian + "IIIIIIII", data, o)
                else:
                    p_type, p_flags = struct.unpack_from(endian + "II", data, o)
                    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                        struct.unpack_from(endian + "QQQQQQ", data, o + 8)
                if p_type == 3 and p_offset < len(data):  # PT_INTERP
                    chunk = data[p_offset:p_offset + min(int(p_filesz), 256)]
                    interp = chunk.split(b"\x00", 1)[0].decode("ascii", "replace")
                if p_type == 2:  # PT_DYNAMIC
                    # walk Dyn entries looking for DT_NEEDED (1) + DT_STRTAB (5)
                    strtab_addr = None
                    needed_offs = []
                    dyn_size = 8 if ei_class == 1 else 16
                    nents = int(p_filesz) // dyn_size if p_filesz else 0
                    for j in range(min(nents, 512)):
                        do = p_offset + j * dyn_size
                        if do + dyn_size > len(data):
                            break
                        if ei_class == 1:
                            d_tag, d_val = struct.unpack_from(endian + "II", data, do)
                        else:
                            d_tag, d_val = struct.unpack_from(endian + "QQ", data, do)
                        if d_tag == 0:
                            break
                        if d_tag == 1:
                            needed_offs.append(d_val)
                        if d_tag == 5:
                            strtab_addr = d_val
                    if strtab_addr is not None:
                        # convert virt to file via sections
                        stroff = None
                        for s in sections:
                            if s["addr"] and s["addr"] <= strtab_addr < s["addr"] + max(s["size"], 1):
                                stroff = s["offset"] + (strtab_addr - s["addr"])
                                break
                        if stroff is None:
                            # sometimes strtab_addr is already a file offset-ish; try as offset
                            if strtab_addr < len(data):
                                stroff = strtab_addr
                        if stroff is not None:
                            for no in needed_offs:
                                start = int(stroff + no)
                                if 0 <= start < len(data):
                                    end = data.find(b"\x00", start, start + 256)
                                    if end == -1:
                                        end = start + 32
                                    needed.append(data[start:end].decode("ascii", "replace"))

        info.update({
            "valid": True,
            "class": ELF_CLASS.get(ei_class, str(ei_class)),
            "endian": ELF_DATA.get(ei_data, str(ei_data)),
            "osabi": ELF_OSABI.get(ei_osabi, str(ei_osabi)),
            "type": ELF_TYPE.get(e_type, "0x%X" % e_type),
            "machine": ELF_MACHINE.get(e_machine, "0x%X" % e_machine),
            "entry": e_entry,
            "phnum": e_phnum,
            "shnum": e_shnum,
            "interp": interp,
            "needed": needed,
            "sections": sections,
        })
    except Exception as e:
        info["warnings"].append("ELF parse error: %s" % e)
    return info


# ---------------------------------------------------------------------------
# DEX / APK
# ---------------------------------------------------------------------------

def parse_dex(data):
    info = {"valid": False}
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        return info
    try:
        ver = data[4:8].split(b"\x00", 1)[0].decode("ascii", "replace")
        file_size = _u32(data, 32)
        header_size = _u32(data, 36)
        endian_tag = _u32(data, 40)
        string_ids = _u32(data, 56)
        type_ids = _u32(data, 64)
        proto_ids = _u32(data, 72)
        field_ids = _u32(data, 80)
        method_ids = _u32(data, 88)
        class_defs = _u32(data, 96)
        data_size = _u32(data, 104)
        info.update({
            "valid": True,
            "version": ver,
            "file_size": file_size,
            "header_size": header_size,
            "endian_tag": "LE" if endian_tag == 0x12345678 else "0x%X" % endian_tag,
            "string_ids": string_ids,
            "type_ids": type_ids,
            "proto_ids": proto_ids,
            "field_ids": field_ids,
            "method_ids": method_ids,
            "class_defs": class_defs,
            "data_size": data_size,
        })
    except Exception as e:
        info["error"] = str(e)
    return info


ANDROID_PERMS_RE = re.compile(
    r"android\.permission\.([A-Z0-9_]+)", re.I
)
INTERESTING_PERMS = {
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "CALL_PHONE",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "CAMERA", "RECORD_AUDIO",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN", "PACKAGE_USAGE_STATS", "WRITE_SECURE_SETTINGS",
    "READ_LOGS", "DUMP", "QUERY_ALL_PACKAGES",
}


def parse_apk(path, data):
    info = {"valid": False, "entries": [], "dex": [], "native": [], "certs": [],
            "permissions": [], "warnings": []}
    if not data.startswith(b"PK"):
        return info
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        info["warnings"].append("zip parse failed: %s" % e)
        return info
    info["valid"] = True
    names = zf.namelist()
    info["entries"] = names[:400]
    info["n_entries"] = len(names)
    for n in names:
        ln = n.lower()
        if ln.endswith(".dex"):
            try:
                raw = zf.read(n)
                d = parse_dex(raw)
                d["name"] = n
                d["size"] = len(raw)
                d["sha256"] = hashlib.sha256(raw).hexdigest()
                info["dex"].append(d)
            except Exception as e:
                info["warnings"].append("dex %s: %s" % (n, e))
        if ln.endswith(".so") or "/lib/" in ln:
            info["native"].append(n)
        if "meta-inf/" in ln and (ln.endswith(".rsa") or ln.endswith(".dsa")
                                  or ln.endswith(".ec") or ln.endswith(".sf")
                                  or ln.endswith(".mf")):
            info["certs"].append(n)
    # permissions from any stored xml / strings in manifest-ish files
    blob_for_strings = b""
    for cand in ("AndroidManifest.xml", "resources.arsc"):
        if cand in names:
            try:
                blob_for_strings += zf.read(cand)[:2_000_000]
            except Exception:
                pass
    # also harvest from all dex strings later; here just binary xml leftovers
    text = ""
    try:
        text = blob_for_strings.decode("utf-8", "ignore")
    except Exception:
        text = ""
    # utf-16le leftover
    try:
        text += blob_for_strings.decode("utf-16le", "ignore")
    except Exception:
        pass
    perms = sorted(set(ANDROID_PERMS_RE.findall(text)))
    # also scan file names / other small text files
    for n in names:
        if n.endswith(".xml") or n.endswith(".txt") or n.endswith(".json"):
            try:
                chunk = zf.read(n)[:200000]
                perms.extend(ANDROID_PERMS_RE.findall(chunk.decode("utf-8", "ignore")))
            except Exception:
                pass
    info["permissions"] = sorted(set(perms))
    info["has_manifest"] = "AndroidManifest.xml" in names
    info["has_resources"] = "resources.arsc" in names
    zf.close()
    return info


# ---------------------------------------------------------------------------
# Strings + IOC harvest
# ---------------------------------------------------------------------------

RE_URL = re.compile(rb"https?://[^\x00-\x1f\"'<>\s]{4,200}", re.I)
RE_URL_S = re.compile(r"https?://[^\x00-\x1f\"'<>\s]{4,200}", re.I)
RE_IP = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_EMAIL = re.compile(rb"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
RE_REG = re.compile(rb"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[\w\\.\- ]{4,180}", re.I)
RE_MUTEX = re.compile(rb"(?:Global|Local)\\[\w.\-]{4,80}", re.I)
RE_PATH_WIN = re.compile(rb"[A-Z]:\\[\w.\\ \-]{5,180}", re.I)
RE_PATH_UNIX = re.compile(rb"/(?:usr|etc|var|tmp|opt|home|data|system|proc)/[\w./\-]{3,160}")
RE_B64 = re.compile(rb"(?:[A-Za-z0-9+/]{32,}={0,2})")
RE_IPV6 = re.compile(rb"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I)
RE_ONION = re.compile(rb"[a-z2-7]{16,56}\.onion\b", re.I)
RE_BTC = re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
RE_BECH32 = re.compile(rb"\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87}\b")
RE_GUID = re.compile(rb"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
RE_PDB = re.compile(rb"[A-Za-z0-9_./\\\- ]+\.pdb", re.I)
RE_DOMAIN = re.compile(r"https?://([^/:\"'\s]+)", re.I)

INTERESTING_STR_RE = re.compile(
    r"(cmd\.exe|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32|"
    r"schtasks|bitsadmin|certutil|curl |wget |base64|"
    r"/bin/sh|/bin/bash|nc -e|python -c|perl -e|"
    r"AppData|Temp\\|\\Startup\\|CurrentVersion\\Run|"
    r"Telegram|Discord|Steal|wallet|seed|mnemonic|bitcoin|monero|"
    r"keylog|screenshot|webcam|clipboard|password|credential|"
    r"debugger|sandbox|vmware|virtualbox|wireshark|procmon|"
    r"accessibility|device.?admin|bind_|"
    r"http[s]?://)",
    re.I,
)


def extract_strings(data, min_len=4, max_strings=8000):
    ascii_strs = []
    wide_strs = []
    # ASCII
    buf = []
    for b in data:
        if 32 <= b < 127:
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                ascii_strs.append("".join(buf))
                if len(ascii_strs) >= max_strings:
                    break
            buf = []
    if len(buf) >= min_len and len(ascii_strs) < max_strings:
        ascii_strs.append("".join(buf))
    # UTF-16LE
    i = 0
    n = len(data)
    while i + 2 <= n and len(wide_strs) < max_strings:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            buf = [chr(lo)]
            i += 2
            while i + 2 <= n:
                lo, hi = data[i], data[i + 1]
                if hi == 0 and 32 <= lo < 127:
                    buf.append(chr(lo))
                    i += 2
                else:
                    break
            if len(buf) >= min_len:
                wide_strs.append("".join(buf))
        else:
            i += 2
    return ascii_strs, wide_strs


BUILD_PATH_MARKERS = (
    "\\agent\\_work\\", "\\src\\", "\\source\\", "\\sources\\",
    "/src/", "/source/",
    "\\visual studio", "\\windows kits\\",
    "\\program files", "\\sdk\\",
)
BUILD_PATH_EXT = (".cpp", ".c", ".cc", ".cxx", ".h", ".hpp", ".cs", ".rs", ".go", ".asm")
KNOWN_FRAMEWORK_PATHS = (
    "wixca", "wcautil", "dutil", "wixwait", "vcredist",
    "microsoft visual", "windows sdk",
)
KNOWN_GOOD_MUTEX = (
    "wixwaitforevent", "zonescachecountermutex", "zoneslockedcachecountermutex",
    "msctf.shared.", "windowspushnotifications",
)


def classify_path(s):
    sl = s.lower()
    if sl.endswith(BUILD_PATH_EXT) or any(m in sl for m in BUILD_PATH_MARKERS):
        return "build"
    if any(m in sl for m in KNOWN_FRAMEWORK_PATHS):
        return "framework"
    if sl.endswith(".pdb"):
        return "pdb"
    return "path"


def classify_mutex(s):
    sl = s.lower()
    if any(m in sl for m in KNOWN_GOOD_MUTEX):
        return "framework"
    return "mutex"


def harvest_iocs(data, ascii_strs, wide_strs):
    iocs = {
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "registry": [],
        "paths": [],
        "build_paths": [],
        "pdb": [],
        "mutex": [],
        "mutex_framework": [],
        "onions": [],
        "wallets": [],
        "interesting": [],
        "b64_blobs": 0,
    }
    for m in RE_URL.finditer(data):
        iocs["urls"].append(m.group().decode("ascii", "replace"))
    for u in iocs["urls"]:
        dm = RE_DOMAIN.search(u)
        if dm:
            host = dm.group(1).lower().rstrip(".")
            if host and host not in iocs["domains"]:
                iocs["domains"].append(host)
    for m in RE_IP.finditer(data):
        ip = m.group().decode("ascii")
        if ip.startswith("0.") or ip.startswith("255."):
            continue
        iocs["ips"].append(ip)
    for m in RE_EMAIL.finditer(data):
        iocs["emails"].append(m.group().decode("ascii", "replace"))
    for m in RE_REG.finditer(data):
        iocs["registry"].append(m.group().decode("ascii", "replace"))
    for m in RE_PATH_WIN.finditer(data):
        s = m.group().decode("ascii", "replace")
        kind = classify_path(s)
        if kind == "build" or kind == "framework":
            iocs["build_paths"].append(s)
        elif kind == "pdb":
            iocs["pdb"].append(s)
        else:
            iocs["paths"].append(s)
    for m in RE_PATH_UNIX.finditer(data):
        s = m.group().decode("ascii", "replace")
        if classify_path(s) in ("build", "framework"):
            iocs["build_paths"].append(s)
        else:
            iocs["paths"].append(s)
    for m in RE_MUTEX.finditer(data):
        s = m.group().decode("ascii", "replace")
        if classify_mutex(s) == "framework":
            iocs["mutex_framework"].append(s)
        else:
            iocs["mutex"].append(s)
    for m in RE_ONION.finditer(data):
        iocs["onions"].append(m.group().decode("ascii", "replace"))
    for rx in (RE_BTC, RE_BECH32):
        for m in rx.finditer(data):
            iocs["wallets"].append(m.group().decode("ascii", "replace"))
    for m in RE_PDB.finditer(data):
        s = m.group().decode("ascii", "replace")
        if s not in iocs["pdb"] and len(s) < 260:
            iocs["pdb"].append(s)
    iocs["b64_blobs"] = len(RE_B64.findall(data))

    seen = set()
    for s in ascii_strs + wide_strs:
        if INTERESTING_STR_RE.search(s):
            key = s[:160]
            if key not in seen:
                seen.add(key)
                iocs["interesting"].append(s[:200])
            if len(iocs["interesting"]) >= 80:
                break

    for k in ("urls", "domains", "ips", "emails", "registry", "paths",
              "build_paths", "pdb", "mutex", "mutex_framework", "onions", "wallets"):
        iocs[k] = list(OrderedDict.fromkeys(iocs[k]))[:80]
    return iocs


def find_pdb_rsds(data):
    """CodeView RSDS leftover: 'RSDS' + 16-byte GUID + age + path."""
    out = []
    start = 0
    while True:
        i = data.find(b"RSDS", start)
        if i < 0 or i + 24 >= len(data):
            break
        age = struct.unpack_from("<I", data, i + 20)[0] if i + 24 <= len(data) else 0
        rest = data[i + 24:i + 24 + 260]
        end = rest.find(b"\x00")
        path = rest[:end if end >= 0 else 260].decode("ascii", "replace")
        if path and ("\\" in path or "/" in path or path.lower().endswith(".pdb")):
            guid = data[i + 4:i + 20].hex()
            out.append({"offset": i, "age": age, "guid": guid, "path": path})
        start = i + 4
        if len(out) >= 8:
            break
    return out


def parse_rich_header(data, e_lfanew):
    """DanS/Rich XOR header used by MSVC link.exe."""
    info = {"present": False}
    if e_lfanew < 0x80:
        return info
    blob = data[:e_lfanew]
    rich = blob.rfind(b"Rich")
    if rich < 0x40:
        return info
    xor_key = struct.unpack_from("<I", data, rich + 4)[0]
    dans = struct.pack("<I", 0x536E6144 ^ xor_key)  # 'DanS'
    dans_off = blob.rfind(dans)
    if dans_off < 0 or dans_off >= rich:
        return info
    entries = []
    off = dans_off + 16
    while off + 8 <= rich:
        masked = struct.unpack_from("<I", data, off)[0] ^ xor_key
        count = struct.unpack_from("<I", data, off + 4)[0] ^ xor_key
        prod = masked >> 16
        build = masked & 0xFFFF
        entries.append({"product": prod, "build": build, "count": count})
        off += 8
    info.update({
        "present": True,
        "offset": dans_off,
        "xor_key": "%08x" % xor_key,
        "entries": entries[:32],
        "n_entries": len(entries),
        "checksum": hashlib.md5(data[dans_off:rich + 8]).hexdigest(),
    })
    return info


def detect_dotnet(data, pe):
    dirs = pe.get("data_dirs") or []
    if len(dirs) > 14 and dirs[14][0] and dirs[14][1]:
        return True
    hay = data[: min(len(data), 2_000_000)]
    return b"mscoree.dll" in hay or b"mscoreei.dll" in hay or b"_CorExeMain" in hay or b"_CorDllMain" in hay


def language_fingerprint(data, pe, sigs):
    tags = []
    if detect_dotnet(data, pe or {}):
        tags.append(".NET/CLR")
    if any(s.startswith("Go ") or s == "Go toolchain" or s == "Go runtime" for s in sigs):
        tags.append("Go")
    if "Rust" in sigs or b"rust_begin_unwind" in data or b".rustc" in data[:4096]:
        tags.append("Rust")
    if b"Borland" in data or b"Delphi" in data[:80000]:
        tags.append("Delphi/Borland")
    if "PyInstaller" in sigs or "_MEIPASS" in "".join(sigs):
        tags.append("Python/PyInstaller")
    if "AutoIt" in sigs or "AutoIt compiled" in sigs:
        tags.append("AutoIt")
    if "NSIS" in sigs:
        tags.append("NSIS installer")
    if "Inno Setup" in sigs:
        tags.append("Inno Setup")
    if pe and pe.get("valid") and not tags:
        tags.append("native PE")
    return list(OrderedDict.fromkeys(tags))


def byte_histogram(data):
    h = [0] * 256
    for b in data:
        h[b] += 1
    return h


def print_histogram(data, width=64):
    h = byte_histogram(data)
    mx = max(h) or 1
    # 16 rows of 16
    lines = []
    for row in range(16):
        cells = []
        for col in range(16):
            v = h[row * 16 + col]
            if v == 0:
                cells.append(C.slate + "·")
            else:
                frac = v / float(mx)
                ch = "▁▂▃▄▅▆▇█"[min(7, int(frac * 8))]
                if frac > 0.6:
                    colr = C.red
                elif frac > 0.25:
                    colr = C.amber
                else:
                    colr = C.moss
                cells.append(colr + ch)
        lines.append("  %s%02x%s %s%s" % (C.slate, row * 16, C.reset, "".join(cells), C.reset))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Packer / compiler heuristics
# ---------------------------------------------------------------------------

PACKER_SIGS = [
    (b"UPX!", "UPX"),
    (b"UPX0", "UPX"),
    (b"UPX1", "UPX"),
    (b"UPX2", "UPX"),
    (b"MPRESS1", "MPRESS"),
    (b"MPRESS2", "MPRESS"),
    (b".themida", "Themida"),
    (b"Themida", "Themida"),
    (b".vmp0", "VMProtect"),
    (b"VMProtect", "VMProtect"),
    (b".aspack", "ASPack"),
    (b"aPLib", "aPLib/ASPack family"),
    (b"PECompact2", "PECompact"),
    (b"PEC2", "PECompact"),
    (b"NSP0", "NsPack"),
    (b"MEW\x00", "MEW"),
    (b"kkrunchy", "kkrunchy"),
    (b"FSG!", "FSG"),
    (b"Petite", "Petite"),
    (b"Obsidium", "Obsidium"),
    (b"ENIGMA", "Enigma Protector"),
    (b"WinLicense", "WinLicense"),
    (b"This program cannot be run in DOS mode", "classic MZ stub"),
    (b"Go build ID:", "Go toolchain"),
    (b"runtime.main", "Go runtime"),
    (b".rdata\x00", "MSVC-ish PE section"),
    (b"Python", "possible Python"),
    (b"PyInstaller", "PyInstaller"),
    (b"PYZ\x00", "PyInstaller PYZ"),
    (b"_MEIPASS", "PyInstaller"),
    (b"AutoIt", "AutoIt"),
    (b"AU3!", "AutoIt compiled"),
    (b"NSIS", "NSIS installer"),
    (b"Nullsoft", "NSIS"),
    (b"Inno Setup", "Inno Setup"),
    (b"Rich\x00", "possible PE Rich header marker nearby"),
    (b"gcc", "possible GCC strings"),
    (b"mingw", "MinGW"),
    (b"rustc", "Rust"),
    (b".rsrc\x00", "PE resources"),
    (b"Dalvik", "Dalvik/Android"),
    (b"AndroidManifest", "Android package"),
    (b"kotlin", "Kotlin"),
    (b"okhttp", "OkHttp (Android net)"),
]


def detect_signatures(data):
    hits = []
    for sig, name in PACKER_SIGS:
        if sig in data:
            hits.append(name)
    return list(OrderedDict.fromkeys(hits))


# ---------------------------------------------------------------------------
# Capability mapping (heuristic, from imports + strings)
# ---------------------------------------------------------------------------

CAP_RULES = [
    ("process injection", "high",
     ("WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection",
      "QueueUserAPC", "NtUnmapViewOfSection", "RtlCreateUserThread")),
    ("memory protection tweak", "med",
     ("VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory")),
    ("remote process open", "med",
     ("OpenProcess", "NtOpenProcess", "OpenThread")),
    ("persistence: registry Run", "high",
     ("CurrentVersion\\Run", "CurrentVersion\\RunOnce", "RegSetValueExA", "RegSetValueExW")),
    ("persistence: service", "high",
     ("CreateService", "StartService", "ChangeServiceConfig")),
    ("persistence: scheduled task", "high",
     ("schtasks", "ITaskService", "TaskScheduler")),
    ("network client", "med",
     ("WSAStartup", "InternetOpen", "WinHttpOpen", "URLDownloadToFile",
      "socket", "connect", "HttpSendRequest")),
    ("HTTP(S) C2-ish", "high",
     ("InternetOpenUrl", "HttpSendRequest", "WinHttpSendRequest", "URLDownloadToFileA")),
    ("credential access", "high",
     ("CryptUnprotectData", "CredEnumerate", "SamIConnect", "VaultEnumerateItems")),
    ("crypto / ransomware-ish", "high",
     ("CryptEncrypt", "BCryptEncrypt", "CryptGenKey", ".onion", "vssadmin", "bcdedit")),
    ("anti-debug", "med",
     ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
      "OutputDebugStringA", "PEB!BeingDebugged")),
    ("anti-VM / sandbox", "med",
     ("VMware", "VirtualBox", "vbox", "sandbox", "SbieDll", "wine_get_unix_file_name")),
    ("keylogging / input", "high",
     ("SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "keylog")),
    ("screenshot / spy", "high",
     ("BitBlt", "GetDC", "CreateCompatibleBitmap", "screenshot", "webcam")),
    ("file drop / execute", "med",
     ("WinExec", "ShellExecute", "CreateProcess", "WriteFile")),
    ("privilege escalation", "high",
     ("AdjustTokenPrivileges", "SeDebugPrivilege", "RtlAdjustPrivilege")),
    ("UAC bypass strings", "high",
     ("fodhelper", "eventvwr", "computerdefaults", "sdclt", "cmstp")),
    ("Android SMS tax", "crit",
     ("SEND_SMS", "RECEIVE_SMS", "content://sms")),
    ("Android overlay / a11y abuse", "crit",
     ("SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "AccessibilityService")),
    ("Android install / admin", "high",
     ("REQUEST_INSTALL_PACKAGES", "BIND_DEVICE_ADMIN", "DeviceAdminReceiver")),
]


def map_capabilities(imports, strings, extra_text=""):
    hay = extra_text + "\n"
    for imp in imports or []:
        hay += (imp.get("dll") or "") + " "
        hay += " ".join(imp.get("funcs") or []) + "\n"
    if isinstance(strings, (list, tuple)):
        hay += "\n".join(strings[:4000])
    else:
        hay += str(strings)
    hay_l = hay
    caps = []
    for name, level, needles in CAP_RULES:
        hits = [n for n in needles if n.lower() in hay_l.lower() or n in hay_l]
        if hits:
            caps.append({"name": name, "level": level, "evidence": hits[:8]})
    return caps


# ---------------------------------------------------------------------------
# Embedded binary carving
# ---------------------------------------------------------------------------

def carve_embedded(data, origin_kind):
    finds = []
    # PE: MZ ... PE\0\0
    start = 0
    if origin_kind == "pe":
        start = 2  # skip own header
    while True:
        i = data.find(b"MZ", start)
        if i < 0 or i + 0x40 >= len(data):
            break
        try:
            e_lfanew = _u32(data, i + 0x3C)
            pe = i + e_lfanew
            if 0x40 <= e_lfanew <= 0x1000 and pe + 4 <= len(data) and data[pe:pe + 4] == b"PE\x00\x00":
                if not (origin_kind == "pe" and i == 0):
                    finds.append({"kind": "PE", "offset": i})
        except Exception:
            pass
        start = i + 2
        if len(finds) >= 8:
            break
    start = 1 if origin_kind == "elf" else 0
    while True:
        i = data.find(b"\x7fELF", start)
        if i < 0:
            break
        if not (origin_kind == "elf" and i == 0):
            finds.append({"kind": "ELF", "offset": i})
        start = i + 4
        if len(finds) >= 12:
            break
    start = 1 if origin_kind == "dex" else 0
    while True:
        i = data.find(b"dex\n", start)
        if i < 0:
            break
        if not (origin_kind == "dex" and i == 0):
            finds.append({"kind": "DEX", "offset": i})
        start = i + 4
        if len(finds) >= 12:
            break
    return finds


# ---------------------------------------------------------------------------
# Risk score (heuristic, labeled as such)
# ---------------------------------------------------------------------------

def risk_score(ctx):
    score = 0
    reasons = []

    ent = ctx.get("entropy", 0)
    if ent >= 7.4:
        score += 18
        reasons.append("very high overall entropy (packed/encrypted?)")
    elif ent >= 7.0:
        score += 10
        reasons.append("high overall entropy")

    pe = ctx.get("pe") or {}
    if pe.get("valid"):
        year = pe.get("compile_year") or 1970
        if year < 1995 or year > utc_dt().year + 1:
            score += 8
            reasons.append("implausible PE timestamp (%s)" % pe.get("compiled"))
        if pe.get("overlay", 0) > 4096:
            score += 6
            reasons.append("overlay present (%s)" % human_size(pe["overlay"]))
        for s in pe.get("sections") or []:
            flags = s.get("flags") or []
            if "EXECUTE" in flags and "WRITE" in flags:
                score += 8
                reasons.append("RWX section %s" % s.get("name"))
            if s.get("entropy", 0) >= 7.2 and s.get("raw_size", 0) > 1024:
                score += 5
                reasons.append("high-entropy section %s" % s.get("name"))
            if s.get("name") in SUSPICIOUS_SECTIONS:
                score += 12
                reasons.append("packer-like section name %s" % s.get("name"))
        for imp in pe.get("imports") or []:
            for f in imp.get("funcs") or []:
                if f in SUSPICIOUS_IMPORTS:
                    score += 2
        if not pe.get("imports"):
            score += 8
            reasons.append("no visible imports (packed or manually reconstructed IAT)")
        dllf = pe.get("dll_flags") or []
        if "NX_COMPAT" not in dllf:
            score += 3
            reasons.append("NX/DEP not advertised")
        if "DYNAMIC_BASE" not in dllf:
            score += 3
            reasons.append("ASLR (DYNAMIC_BASE) not advertised")

    if ctx.get("sigs"):
        packers = [s for s in ctx["sigs"] if s not in
                   ("classic MZ stub", "MSVC-ish PE section", "PE resources",
                    "possible GCC strings", "possible PE Rich header marker nearby")]
        if packers:
            score += 10
            reasons.append("packer/compiler signatures: %s" % ", ".join(packers[:6]))

    for cap in ctx.get("caps") or []:
        add = {"low": 3, "med": 6, "high": 10, "crit": 14}.get(cap["level"], 4)
        score += add
        reasons.append("capability: %s" % cap["name"])

    iocs = ctx.get("iocs") or {}
    if iocs.get("urls"):
        score += min(12, 3 * len(iocs["urls"][:4]))
        reasons.append("%d URL(s) in strings" % len(iocs["urls"]))
    if iocs.get("ips"):
        score += min(10, 2 * len(iocs["ips"][:5]))
        reasons.append("%d IPv4 candidate(s)" % len(iocs["ips"]))

    if ctx.get("carved"):
        score += 8
        reasons.append("embedded PE/ELF/DEX found")

    apk = ctx.get("apk") or {}
    if apk.get("valid"):
        dang = [p for p in apk.get("permissions") or [] if p in INTERESTING_PERMS]
        if dang:
            score += min(20, 3 * len(dang))
            reasons.append("sensitive Android permissions: %s" % ", ".join(dang[:8]))

    score = max(0, min(100, score))
    if score >= 70:
        label, level = "HOSTILE-LOOKING", "crit"
    elif score >= 45:
        label, level = "SUSPICIOUS", "high"
    elif score >= 25:
        label, level = "INTERESTING", "med"
    elif score >= 10:
        label, level = "WEAK SIGNALS", "low"
    else:
        label, level = "QUIET / BENIGN-LEANING", "ok"
    return score, label, level, reasons


# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------

def hexdump(data, offset=0, length=256, base=0):
    chunk = data[offset:offset + length]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hexpart = " ".join("%02x" % b for b in row)
        hexpart = hexpart.ljust(16 * 3 - 1)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        addr = base + offset + i
        lines.append("  %s%08x%s  %s%s%s  %s%s%s" % (
            C.slate, addr, C.reset,
            C.ice, hexpart, C.reset,
            C.gold, asci, C.reset,
        ))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Optional external helpers
# ---------------------------------------------------------------------------

def yara_scan(path):
    if not which("yara"):
        return None
    # user may have rules; try common locations + env
    rules = []
    envr = os.environ.get("NECROBIN_YARA")
    if envr and os.path.exists(envr):
        rules.append(envr)
    for cand in (
        os.path.expanduser("~/.necrobin/rules.yar"),
        "/usr/local/share/yara/index.yar",
        "/usr/share/yara/rules/index.yar",
    ):
        if os.path.exists(cand):
            rules.append(cand)
    if not rules:
        return {"available": True, "hits": [], "note": "yara binary present but no rules file found. Set NECROBIN_YARA=/path/to/rules.yar"}
    hits = []
    for r in rules:
        rc, out, err = run_cmd(["yara", "-w", r, path], timeout=30)
        if out.strip():
            for line in out.splitlines():
                hits.append(line.strip())
    return {"available": True, "hits": hits, "rules": rules}


def vt_lookup(sha256):
    key = os.environ.get("NECROBIN_VT_KEY") or os.environ.get("VT_API_KEY")
    if not key:
        return None
    # prefer curl to avoid requests dependency
    if not which("curl"):
        return {"error": "curl not installed; cannot query VirusTotal"}
    url = "https://www.virustotal.com/api/v3/files/%s" % sha256
    rc, out, err = run_cmd([
        "curl", "-sS", "--max-time", "20",
        "-H", "x-apikey: %s" % key,
        url,
    ], timeout=25)
    if rc != 0:
        return {"error": err or "curl failed"}
    try:
        js = json.loads(out)
    except Exception:
        return {"error": "VT returned non-JSON"}
    if "error" in js:
        return {"error": js["error"].get("message", str(js["error"]))}
    stats = (((js.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    names = ((js.get("data") or {}).get("attributes") or {}).get("popular_threat_classification") or {}
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "label": (names.get("suggested_threat_label") if isinstance(names, dict) else None),
    }


def bazaar_lookup(sha256):
    """Hash-only query to abuse.ch MalwareBazaar. Sends no file bytes."""
    if not which("curl"):
        return {"error": "curl not installed"}
    rc, out, err = run_cmd([
        "curl", "-sS", "--max-time", "20",
        "-d", "query=get_info&hash=%s" % sha256,
        "https://mb-api.abuse.ch/api/v1/",
    ], timeout=25)
    if rc != 0:
        return {"error": err or "curl failed"}
    try:
        js = json.loads(out)
    except Exception:
        return {"error": "non-JSON response"}
    status = js.get("query_status")
    if status != "ok":
        return {"query_status": status or "unknown"}
    data = js.get("data") or []
    first = data[0] if data else {}
    return {
        "query_status": "ok",
        "count": len(data),
        "family": first.get("signature") or first.get("malware"),
        "signature": first.get("signature"),
        "tags": first.get("tags"),
        "file_type": first.get("file_type"),
        "first_seen": first.get("first_seen"),
    }


STARTER_YARA = r'''
rule necrobin_mz_pe
{
    meta:
        description = "MZ header with PE signature"
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}

rule necrobin_elf
{
    condition:
        uint32(0) == 0x464C457F
}

rule necrobin_upx
{
    strings:
        $a = "UPX0"
        $b = "UPX1"
        $c = "UPX!"
    condition:
        2 of them
}

rule necrobin_pyinstaller
{
    strings:
        $a = "_MEIPASS"
        $b = "PyInstaller"
        $c = "PYZ"
    condition:
        2 of them
}

rule necrobin_wix_customaction
{
    meta:
        description = "WiX custom action / installer framework leftovers"
    strings:
        $a = "WixWaitForEventFail"
        $b = "WixWaitForEventSucceed"
        $c = "wixca"
    condition:
        2 of them
}
'''


def write_starter_yara(path=None):
    path = path or os.path.expanduser("~/.necrobin/rules.yar")
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    if os.path.exists(path):
        return path, False
    with open(path, "w", encoding="utf-8") as f:
        f.write(STARTER_YARA.lstrip("\n"))
    return path, True


# ---------------------------------------------------------------------------
# Disassembly (capstone / ndisasm / tiny decoder)
# ---------------------------------------------------------------------------

def _entry_file_off(pe):
    if not pe or not pe.get("valid"):
        return None
    rva = pe.get("entry_rva") or 0
    return rva_to_off(rva, pe.get("sections") or [])


def _arch_mode(pe=None, elf=None):
    if pe and pe.get("valid"):
        m = pe.get("machine") or ""
        if m in ("AMD64", "IA64", "ARM64"):
            return "x64" if m != "ARM64" else "arm64"
        if m in ("I386",):
            return "x86"
        if m in ("ARM", "ARMNT"):
            return "arm"
        return "x86"
    if elf and elf.get("valid"):
        m = elf.get("machine") or ""
        if m in ("X86_64", "AARCH64"):
            return "x64" if m == "X86_64" else "arm64"
        if m in ("386",):
            return "x86"
        if m == "ARM":
            return "arm"
    return "x86"


def _load_capstone():
    """Return (module, error). Debian's python3-capstone should import as 'capstone'."""
    err = None
    for name in ("capstone",):
        try:
            return __import__(name), None
        except Exception as e:
            err = "%s (%s)" % (type(e).__name__, e)
    return None, err


def disasm_bytes(code, arch="x86", origin=0, max_ins=40):
    """Return list of {addr, hex, text, src}."""
    out = []
    if not code:
        return out
    code = bytes(code)
    cs_err = None
    cs, cs_err = _load_capstone()
    if cs is not None:
        le = getattr(cs, "CS_MODE_LITTLE_ENDIAN", 0)
        maps = {
            "x86": [(cs.CS_ARCH_X86, cs.CS_MODE_32)],
            "x64": [(cs.CS_ARCH_X86, cs.CS_MODE_64)],
            "arm": [(cs.CS_ARCH_ARM, cs.CS_MODE_ARM | le)],
            "arm64": [(getattr(cs, "CS_ARCH_ARM64", cs.CS_ARCH_ARM),
                       getattr(cs, "CS_MODE_ARM", 0) | le)],
        }
        # packed x86 stubs are often 32-bit even inside a PE32+ file; try both
        if arch in ("x86", "x64"):
            order = maps["x64"] + maps["x86"] if arch == "x64" else maps["x86"] + maps["x64"]
        else:
            order = maps.get(arch) or maps["x86"]
        for a, m in order:
            try:
                md = cs.Cs(a, m)
                md.detail = False
                tmp = []
                for i, ins in enumerate(md.disasm(code, origin)):
                    if i >= max_ins:
                        break
                    tmp.append({
                        "addr": ins.address,
                        "hex": ins.bytes.hex(),
                        "text": ("%s %s" % (ins.mnemonic, ins.op_str)).strip(),
                        "src": "capstone",
                    })
                if tmp:
                    return tmp
            except Exception as e:
                cs_err = "%s" % e
                continue
        if cs_err is None:
            cs_err = "capstone imported but decoded 0 instructions (wrong arch or truncated EP bytes)"
    if which("ndisasm"):
        bits = "64" if arch == "x64" else "32"
        rc, stdout, _ = run_cmd(["ndisasm", "-b", bits, "-"], timeout=8, input_bytes=code[:512])
        if rc == 0:
            for i, line in enumerate(stdout.splitlines()):
                if i >= max_ins:
                    break
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        addr = int(parts[0], 16)
                    except ValueError:
                        continue
                    out.append({"addr": addr if addr > origin else origin + addr,
                                "hex": parts[1], "text": " ".join(parts[2:]), "src": "ndisasm"})
            if out:
                return out
    why = cs_err or "capstone module not importable by %s" % sys.executable
    chunk = code[:16]
    out.append({
        "addr": origin,
        "hex": "".join("%02x" % b for b in chunk),
        "text": "no decode — %s" % why,
        "src": "raw",
    })
    return out


def oep_heuristics(pe):
    notes = []
    if not pe or not pe.get("valid"):
        return notes
    ep = pe.get("entry_rva") or 0
    sect = None
    for s in pe.get("sections") or []:
        vs = max(s.get("vsize") or 0, s.get("raw_size") or 0)
        if s["vaddr"] <= ep < s["vaddr"] + max(vs, 1):
            sect = s
            break
    if sect:
        notes.append("entry falls in section %s (ent=%.3f)" % (sect.get("name"), sect.get("entropy") or 0))
        if sect.get("name") in SUSPICIOUS_SECTIONS or str(sect.get("name", "")).upper().startswith("UPX"):
            notes.append("OEP-looking: entry is inside a packer section (real OEP is after unpack)")
        if (sect.get("entropy") or 0) >= 7.2:
            notes.append("entry section is high-entropy — packed stub more likely than real OEP")
        flags = sect.get("flags") or []
        if "EXECUTE" not in flags:
            notes.append("entry section is not marked EXECUTE (odd / overlay-style)")
    else:
        notes.append("entry RVA 0x%X is outside parsed sections" % ep)
    return notes


def iat_hints(data, pe):
    """Look for runs of 4/8-byte pointers that land inside the import section."""
    hints = []
    if not pe or not pe.get("valid"):
        return hints
    dirs = pe.get("data_dirs") or []
    if len(dirs) < 2 or not dirs[1][0]:
        hints.append("no import directory — IAT may be rebuilt at runtime")
        return hints
    imp_rva, imp_sz = dirs[1]
    # data dir 12 is IAT
    iat = dirs[12] if len(dirs) > 12 else (0, 0)
    if iat[0]:
        hints.append("IAT data directory RVA=0x%X size=0x%X" % (iat[0], iat[1]))
    else:
        hints.append("IAT data directory empty — search thunks near imports RVA 0x%X" % imp_rva)
    if not pe.get("imports"):
        hints.append("parsed import names: none. Hunt for LoadLibrary/GetProcAddress or a handwritten IAT")
    return hints


# ---------------------------------------------------------------------------
# XOR / encoded strings / stack strings / base64 re-analysis
# ---------------------------------------------------------------------------

def _printable_runs(buf, min_len=8):
    runs = []
    cur = []
    for b in buf:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                runs.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        runs.append("".join(cur))
    return runs


def xor_bruteforce(data, max_scan=262144, top_k=6):
    """Single-byte XOR 0x01-0xFF. Rank keys by long printable runs."""
    blob = data[:max_scan]
    if len(blob) < 16:
        return []
    scored = []
    # sample every byte of a stride to keep this cheap on big files
    step = 1 if len(blob) < 65536 else 2
    sample = blob[::step]
    for key in range(1, 256):
        dec = bytes(b ^ key for b in sample)
        runs = [r for r in _printable_runs(dec, min_len=12) if len(set(r)) >= 5]
        if not runs:
            continue
        score = sum(len(r) for r in runs)
        if any("http" in r.lower() or "this program" in r.lower() for r in runs):
            score += 80
        if score < 48:
            continue
        scored.append((score, key, runs[:8]))
    scored.sort(reverse=True)
    results = []
    seen_text = set()
    for score, key, runs in scored[:top_k]:
        # decode a denser window for nicer strings
        window = bytes(b ^ key for b in blob[: min(len(blob), 65536)])
        full_runs = [r for r in _printable_runs(window, min_len=10) if r not in seen_text]
        for r in full_runs[:12]:
            seen_text.add(r)
        magic = None
        head = bytes(b ^ key for b in data[:4])
        if head[:2] == b"MZ":
            magic = "XOR-decoded header looks like PE"
        elif head[:4] == b"\x7fELF":
            magic = "XOR-decoded header looks like ELF"
        elif head[:2] == b"PK":
            magic = "XOR-decoded header looks like ZIP/APK"
        results.append({
            "key": key,
            "key_hex": "0x%02X" % key,
            "score": score,
            "strings": full_runs[:12],
            "magic": magic,
        })
    return results


def xor_common_keys(data, max_scan=131072):
    """Try popular constants + 00/FF-padded ASCII."""
    blob = data[:max_scan]
    hits = []
    popular = (0x20, 0x22, 0x33, 0x41, 0x55, 0x66, 0x80, 0xAA, 0xCC, 0xDD, 0xEE, 0xFF)
    for key in popular:
        dec = bytes(b ^ key for b in blob)
        runs = [r for r in _printable_runs(dec, min_len=12) if any(c.isalpha() for c in r)]
        if runs:
            hits.append({"key": "0x%02X" % key, "strings": runs[:8]})
    # 0x00 padded already covered by wide strings; 0xFF padded: A FF B FF C
    ff_chars = []
    i = 0
    n = len(blob)
    while i + 2 <= n:
        if blob[i + 1] == 0xFF and 32 <= blob[i] < 127:
            buf = [chr(blob[i])]
            i += 2
            while i + 2 <= n and blob[i + 1] == 0xFF and 32 <= blob[i] < 127:
                buf.append(chr(blob[i]))
                i += 2
            if len(buf) >= 6:
                ff_chars.append("".join(buf))
        else:
            i += 1
    if ff_chars:
        hits.append({"key": "0xFF-padded", "strings": list(OrderedDict.fromkeys(ff_chars))[:12]})
    return hits


def recover_stack_strings(data, max_scan=524288):
    """Heuristic: consecutive mov [ebp/esp+disp], imm{8,32} building ASCII."""
    blob = data[:max_scan]
    found = []
    n = len(blob)
    i = 0
    stores = []  # (offset_in_file, disp, byte_or_none)

    def flush():
        if len(stores) < 4:
            stores.clear()
            return
        # group by nearby file offsets
        stores.sort(key=lambda x: x[1])
        chars = []
        last_disp = None
        for _off, disp, ch in stores:
            if last_disp is not None and disp not in (last_disp + 1, last_disp + 4, last_disp):
                if len(chars) >= 4:
                    s = "".join(chars)
                    if any(c.isalpha() for c in s):
                        found.append(s)
                chars = []
            if ch is not None:
                chars.append(ch)
            last_disp = disp
        if len(chars) >= 4:
            s = "".join(chars)
            if any(c.isalpha() for c in s):
                found.append(s)
        stores.clear()

    while i < n - 6:
        b0 = blob[i]
        # C6 45 xx yy    mov byte [ebp+disp8], imm8
        if b0 == 0xC6 and i + 3 < n and blob[i + 1] == 0x45:
            stores.append((i, blob[i + 2] if blob[i + 2] < 128 else blob[i + 2] - 256, chr(blob[i + 3]) if 32 <= blob[i + 3] < 127 else None))
            i += 4
            continue
        # C6 44 24 xx yy  mov byte [esp+disp8], imm8
        if b0 == 0xC6 and i + 4 < n and blob[i + 1] == 0x44 and blob[i + 2] == 0x24:
            stores.append((i, blob[i + 3], chr(blob[i + 4]) if 32 <= blob[i + 4] < 127 else None))
            i += 5
            continue
        # C7 45 xx imm32  mov dword [ebp+disp8], imm32
        if b0 == 0xC7 and i + 6 < n and blob[i + 1] == 0x45:
            imm = blob[i + 3:i + 7]
            for j, ch in enumerate(imm):
                if 32 <= ch < 127:
                    stores.append((i, (blob[i + 2] if blob[i + 2] < 128 else blob[i + 2] - 256) + j, chr(ch)))
            i += 7
            continue
        # C7 44 24 xx imm32
        if b0 == 0xC7 and i + 7 < n and blob[i + 1] == 0x44 and blob[i + 2] == 0x24:
            imm = blob[i + 4:i + 8]
            for j, ch in enumerate(imm):
                if 32 <= ch < 127:
                    stores.append((i, blob[i + 3] + j, chr(ch)))
            i += 8
            continue
        # gap — flush current builder
        if stores and i - stores[-1][0] > 24:
            flush()
        i += 1
    flush()
    return list(OrderedDict.fromkeys(found))[:40]


def decode_base64_blobs(data, ascii_strs):
    hits = []
    candidates = []
    for m in RE_B64.finditer(data[:1048576]):
        candidates.append(m.group().decode("ascii", "replace"))
    for s in ascii_strs:
        if len(s) >= 32 and re.fullmatch(r"[A-Za-z0-9+/]+=*", s or ""):
            candidates.append(s)
    seen = set()
    for raw in candidates:
        if raw in seen or len(raw) > 8000:
            continue
        seen.add(raw)
        pad = "=" * ((4 - (len(raw) % 4)) % 4)
        try:
            import base64
            dec = base64.b64decode(raw + pad, validate=False)
        except Exception:
            continue
        if len(dec) < 8:
            continue
        kind = "bytes"
        extra = ""
        if dec[:2] == b"MZ":
            kind = "PE"
        elif dec[:4] == b"\x7fELF":
            kind = "ELF"
        elif dec[:2] == b"PK":
            kind = "ZIP"
        elif dec[:4] == b"dex\n":
            kind = "DEX"
        else:
            text_runs = _printable_runs(dec, min_len=8)
            if text_runs:
                kind = "text"
                extra = text_runs[0][:160]
        urls = [m.group().decode("ascii", "replace") for m in RE_URL.finditer(dec)]
        hits.append({
            "preview": raw[:48] + ("…" if len(raw) > 48 else ""),
            "decoded_len": len(dec),
            "kind": kind,
            "text": extra,
            "urls": urls[:6],
            "sha256": hashlib.sha256(dec).hexdigest()[:16],
        })
        if len(hits) >= 20:
            break
    return hits


def reconstruct_split_urls(ascii_strs):
    """Join neighboring short strings that form an http URL."""
    out = []
    n = len(ascii_strs)
    for i, s in enumerate(ascii_strs[:3000]):
        sl = s.lower()
        if sl in ("http", "https", "http:", "https:", "http://", "https://") or sl.startswith("http"):
            acc = s
            for j in range(1, 5):
                if i + j >= n:
                    break
                nxt = ascii_strs[i + j]
                if len(nxt) > 80:
                    break
                acc += nxt
                if RE_URL_S.search(acc):
                    out.append(acc[:200])
                    break
        # "hxxp" defanged
        if sl.startswith("hxxp"):
            out.append(s.replace("hxxp", "http").replace("[.]", ".")[:200])
    return list(OrderedDict.fromkeys(out))[:30]


def dga_like_domains(domains):
    hits = []
    vowels = set("aeiou")
    for d in domains or []:
        host = d.split(":")[0].strip(".").lower()
        labels = [x for x in host.split(".") if x and x not in ("www", "com", "net", "org", "io", "co")]
        if not labels:
            continue
        sld = labels[0]
        if len(sld) < 10:
            continue
        if any(ch.isdigit() for ch in sld) and sum(ch.isalpha() for ch in sld) >= 8:
            pass
        ent = shannon_entropy(sld.encode("ascii", "replace"))
        v = sum(1 for c in sld if c in vowels) / float(len(sld))
        if ent >= 3.3 and v < 0.28 and re.fullmatch(r"[a-z0-9\-]+", sld):
            hits.append({"domain": host, "label": sld, "entropy": round(ent, 3), "vowel_ratio": round(v, 3)})
    return hits[:20]


FAMILY_HINTS = [
    ("Emotet", ("geodo", "heodo", "emotet", "outlook.exe", "regsvr32")),
    ("QakBot", ("qbot", "qakbot", "tkn_", "autoelevate")),
    ("IcedID", ("icedid", "bokbot", "license.dat")),
    ("Cobalt Strike", ("%s.%s.%s.%s", "beacon.dll", "ReflectiveLoader", "pipeline")),
    ("Metasploit", ("meterpreter", "msfvenom", "PAYLOAD:")),
    ("AsyncRAT / Quasar-ish", ("AsyncRAT", "QuasarClient", "LimeRAT")),
    ("RedLine / stealers", ("redline", "stealerserver", "%appdata%\\")),
]


def family_hints(data, ascii_strs, iocs):
    hay = b" ".join([data[:400000]] + [s.encode("utf-8", "replace") for s in (ascii_strs or [])[:400]])
    hay_l = hay.lower()
    hits = []
    for name, needles in FAMILY_HINTS:
        ev = []
        for n in needles:
            if n.encode("utf-8").lower() in hay_l:
                ev.append(n)
        if ev:
            hits.append({"family": name, "evidence": ev, "note": "string fingerprint only — not a config extractor"})
    return hits


# ---------------------------------------------------------------------------
# Advanced PE directories
# ---------------------------------------------------------------------------

def parse_tls(data, pe):
    info = {"present": False, "callbacks": []}
    dirs = (pe or {}).get("data_dirs") or []
    if len(dirs) < 10 or not dirs[9][0]:
        return info
    off = rva_to_off(dirs[9][0], pe.get("sections") or [])
    if off is None:
        info["present"] = True
        info["note"] = "TLS directory RVA 0x%X not mapped to a file offset" % dirs[9][0]
        return info
    pe32plus = pe.get("pe32plus")
    try:
        if pe32plus:
            if off + 40 > len(data):
                return info
            addr_cb = _u64(data, off + 24)
        else:
            if off + 24 > len(data):
                return info
            addr_cb = _u32(data, off + 12)
        info["present"] = True
        info["callbacks_rva"] = addr_cb
        cb_off = rva_to_off(addr_cb, pe.get("sections") or []) if addr_cb else None
        ptr = 8 if pe32plus else 4
        if cb_off is not None:
            for i in range(16):
                o = cb_off + i * ptr
                val = _u64(data, o) if pe32plus else _u32(data, o)
                if val == 0:
                    break
                info["callbacks"].append(val)
    except Exception as e:
        info["note"] = str(e)
    return info


def parse_delay_imports(data, pe):
    result = []
    dirs = (pe or {}).get("data_dirs") or []
    if len(dirs) < 14 or not dirs[13][0]:
        return result
    off = rva_to_off(dirs[13][0], pe.get("sections") or [])
    if off is None:
        return result
    # IMAGE_DELAYLOAD_DESCRIPTOR 32 bytes
    for i in range(64):
        o = off + i * 32
        if o + 32 > len(data):
            break
        attrs = _u32(data, o)
        name_rva = _u32(data, o + 4)
        if attrs == 0 and name_rva == 0:
            break
        name = ""
        no = rva_to_off(name_rva, pe.get("sections") or []) if name_rva else None
        if no is not None:
            end = data.find(b"\x00", no, no + 128)
            name = data[no:end if end >= 0 else no + 32].decode("ascii", "replace")
        result.append({"dll": name, "name_rva": name_rva})
    return result


def parse_exceptions(data, pe):
    info = {"present": False, "count": 0}
    dirs = (pe or {}).get("data_dirs") or []
    if len(dirs) < 4 or not dirs[3][0] or not dirs[3][1]:
        return info
    info["present"] = True
    info["rva"] = dirs[3][0]
    info["size"] = dirs[3][1]
    # x64 RUNTIME_FUNCTION is 12 bytes
    if pe.get("machine") == "AMD64":
        info["count"] = dirs[3][1] // 12
    else:
        info["count"] = dirs[3][1] // 20 if dirs[3][1] else 0
    return info


def parse_bound_imports(data, pe):
    names = []
    dirs = (pe or {}).get("data_dirs") or []
    if len(dirs) < 12 or not dirs[11][0]:
        return names
    # bound import is often an RVA from the start of the image... actually it's a file offset from beginning of PE sometimes
    # Microsoft: Bound Import is an RVA from the start of the raw image (offset from image base conceptually) but typically stored as offset from PE start in file for this directory...
    # Practically it's an RVA relative to the image; many files store it as an offset from the start of the file within headers.
    rva = dirs[11][0]
    off = rva
    if off >= len(data):
        off2 = rva_to_off(rva, pe.get("sections") or [])
        off = off2 if off2 is not None else rva
    if off is None or off + 8 > len(data):
        return names
    try:
        base = off
        for _ in range(32):
            ts = _u32(data, off)
            name_off = _u16(data, off + 4)
            _mod = _u16(data, off + 6)
            if ts == 0 and name_off == 0:
                break
            npos = base + name_off
            if 0 <= npos < len(data):
                end = data.find(b"\x00", npos, npos + 128)
                names.append(data[npos:end if end >= 0 else npos + 32].decode("ascii", "replace"))
            off += 8
    except Exception:
        pass
    return [n for n in names if n]


RT_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
    10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
}


def _res_name(data, off, is_name):
    if not is_name:
        return off
    # Name is RVA-ish offset from resource dir start — handled by caller
    return off


def parse_resources(data, pe):
    info = {"present": False, "entries": [], "version": {}, "manifest_preview": "", "rcdata": 0}
    dirs = (pe or {}).get("data_dirs") or []
    if len(dirs) < 3 or not dirs[2][0]:
        return info
    root = rva_to_off(dirs[2][0], pe.get("sections") or [])
    if root is None:
        return info
    info["present"] = True
    base_rva = dirs[2][0]

    def read_dir(off, depth, type_name):
        if depth > 3 or off + 16 > len(data) or len(info["entries"]) > 80:
            return
        named = _u16(data, off + 12)
        ids = _u16(data, off + 14)
        total = min(named + ids, 64)
        for i in range(total):
            eoff = off + 16 + i * 8
            if eoff + 8 > len(data):
                break
            name = _u32(data, eoff)
            ptr = _u32(data, eoff + 4)
            is_name = bool(name & 0x80000000)
            raw_id = name & 0x7FFFFFFF
            label = type_name
            if depth == 0:
                label = RT_TYPES.get(raw_id, "#%d" % raw_id) if not is_name else "NAME"
            if ptr & 0x80000000:
                sub = root + (ptr & 0x7FFFFFFF)
                read_dir(sub, depth + 1, label)
            else:
                # data entry
                de = root + ptr
                if de + 16 > len(data):
                    continue
                data_rva = _u32(data, de)
                data_sz = _u32(data, de + 4)
                doff = rva_to_off(data_rva, pe.get("sections") or [])
                info["entries"].append({"type": label, "size": data_sz, "rva": data_rva})
                if label == "RCDATA":
                    info["rcdata"] += 1
                if label == "VERSION" and doff is not None:
                    blob = data[doff:doff + min(data_sz, 4096)]
                    # pull UTF-16 pairs of interest
                    try:
                        wide = blob.decode("utf-16le", "ignore")
                    except Exception:
                        wide = ""
                    for key in ("FileDescription", "FileVersion", "ProductName",
                                "ProductVersion", "OriginalFilename", "CompanyName",
                                "InternalName", "LegalCopyright"):
                        idx = wide.find(key)
                        if idx >= 0:
                            tail = wide[idx + len(key):idx + len(key) + 80]
                            tail = "".join(ch for ch in tail if 32 <= ord(ch) < 127).strip()
                            if tail:
                                info["version"][key] = tail[:60]
                if label == "MANIFEST" and doff is not None:
                    blob = data[doff:doff + min(data_sz, 400)]
                    info["manifest_preview"] = blob.decode("utf-8", "replace")[:300]

    try:
        read_dir(root, 0, "?")
    except Exception as e:
        info["error"] = str(e)
    # collapse counts
    counts = Counter(e["type"] for e in info["entries"])
    info["summary"] = dict(counts)
    return info


# ---------------------------------------------------------------------------
# Extra file formats: Java class, OLE/OOXML, PDF
# ---------------------------------------------------------------------------

def parse_java_class(data):
    info = {"valid": False}
    if data[:4] != b"\xca\xfe\xba\xbe" or len(data) < 10:
        return info
    # fat Mach-O also uses cafe babe with small nfat; skip if it looks like fat
    nfat = struct.unpack(">I", data[4:8])[0]
    if nfat < 16 and len(data) > 16:
        # could be fat; don't treat as class if next looks like arch
        return info
    try:
        minor, major = struct.unpack(">HH", data[4:8])
        cp_count = struct.unpack(">H", data[8:10])[0]
        strings = []
        i = 10
        idx = 1
        while idx < cp_count and i + 3 <= len(data) and len(strings) < 200:
            tag = data[i]
            i += 1
            if tag == 1:  # Utf8
                ln = struct.unpack(">H", data[i:i + 2])[0]
                i += 2
                s = data[i:i + ln].decode("utf-8", "replace")
                i += ln
                strings.append(s)
            elif tag in (7, 8, 16, 19, 20):
                i += 2
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                i += 4
            elif tag in (5, 6):
                i += 8
                idx += 1
            elif tag == 15:
                i += 3
            else:
                break
            idx += 1
        info.update({
            "valid": True,
            "major": major,
            "minor": minor,
            "cp_strings": strings[:80],
            "interesting": [s for s in strings if INTERESTING_STR_RE.search(s) or s.startswith("http") or "/" in s][:40],
        })
    except Exception as e:
        info["error"] = str(e)
    return info


def parse_ole(data):
    info = {"valid": False, "streams": []}
    if data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return info
    info["valid"] = True
    # directory entries are 128 bytes; names are UTF-16LE first 64
    # sector size from header offset 30
    try:
        shift = _u16(data, 30)
        sect = 1 << shift if 6 <= shift <= 12 else 512
    except Exception:
        sect = 512
    # brute: every 128-byte aligned block look like a dirent name
    names = []
    for off in range(sect, min(len(data), 2_000_000), 128):
        raw = data[off:off + 64]
        if raw[0:2] == b"\x00\x00":
            continue
        try:
            nm = raw.decode("utf-8", "ignore")
        except Exception:
            nm = ""
        try:
            nm16 = raw.decode("utf-16le", "ignore").split("\x00", 1)[0]
        except Exception:
            nm16 = ""
        cand = nm16 if len(nm16) > 1 else ""
        if cand and all(32 <= ord(c) < 127 or c in "\x05\x01" for c in cand):
            names.append(cand.strip())
    info["streams"] = list(OrderedDict.fromkeys(names))[:40]
    blob = " ".join(info["streams"]).lower()
    info["has_vba"] = any(x in blob for x in ("vba", "macros", "_vba_project", "dir"))
    info["kind_guess"] = (
        "Word" if "worddocument" in blob else
        "Excel" if "workbook" in blob or "book" in blob else
        "PowerPoint" if "powerpoint" in blob else
        "OLE"
    )
    return info


def parse_ooxml(data, path):
    info = {"valid": False}
    if not data.startswith(b"PK"):
        return info
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return info
    names = zf.namelist()
    info["valid"] = True
    info["entries"] = names[:80]
    info["n"] = len(names)
    info["is_office"] = any(n.startswith(("word/", "xl/", "ppt/")) for n in names)
    info["macros"] = [n for n in names if "vba" in n.lower() or n.endswith(".bin")]
    info["has_macros"] = any("vbaProject.bin" in n for n in names)
    info["content_types"] = "word" if any(n.startswith("word/") for n in names) else (
        "excel" if any(n.startswith("xl/") for n in names) else (
            "ppt" if any(n.startswith("ppt/") for n in names) else "zip"))
    zf.close()
    return info


def parse_pdf(data):
    info = {"valid": data.startswith(b"%PDF"), "js": False, "openaction": False,
            "aa": False, "embedded": False, "streams": 0, "uris": [], "js_snippets": []}
    if not info["valid"]:
        return info
    sample = data[: min(len(data), 2_000_000)]
    info["streams"] = sample.count(b"stream")
    info["js"] = b"/JavaScript" in sample or b"/JS" in sample
    info["openaction"] = b"/OpenAction" in sample
    info["aa"] = b"/AA" in sample
    info["embedded"] = b"/EmbeddedFile" in sample
    for m in re.finditer(rb"/\s*URI\s*\(([^)]{4,180})\)", sample):
        info["uris"].append(m.group(1).decode("latin-1", "replace"))
    # crude JS snippets between parentheses after /JS
    for m in re.finditer(rb"/JS\s*\(([^)]{8,240})\)", sample):
        info["js_snippets"].append(m.group(1).decode("latin-1", "replace")[:200])
    for m in re.finditer(rb"/JavaScript\s*<<[^>]{0,40}/JS\s*\(([^)]{8,240})\)", sample):
        info["js_snippets"].append(m.group(1).decode("latin-1", "replace")[:200])
    info["uris"] = list(OrderedDict.fromkeys(info["uris"]))[:20]
    info["js_snippets"] = list(OrderedDict.fromkeys(info["js_snippets"]))[:10]
    return info


# ---------------------------------------------------------------------------
# UPX unpack assist (external upx binary only)
# ---------------------------------------------------------------------------

def upx_unpack(path, data):
    info = {"available": bool(which("upx")), "packed": False, "unpacked": None, "error": None}
    if b"UPX!" in data or b"UPX0" in data or b"UPX1" in data:
        info["packed"] = True
    if not info["available"]:
        if info["packed"]:
            info["error"] = "UPX stub detected but `upx` binary is not on PATH"
        return info
    if not info["packed"]:
        return info
    dest = path + ".unpacked"
    rc, out, err = run_cmd(["upx", "-d", "-o", dest, path], timeout=30)
    if rc == 0 and os.path.isfile(dest):
        info["unpacked"] = dest
        info["unpacked_size"] = os.path.getsize(dest)
    else:
        info["error"] = (err or out or "upx -d failed").strip()[:240]
        if os.path.isfile(dest) and os.path.getsize(dest) == 0:
            try:
                os.remove(dest)
            except Exception:
                pass
    return info

# ---------------------------------------------------------------------------
# Full analysis
# ---------------------------------------------------------------------------

class Autopsy(object):
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.exists = os.path.isfile(self.path)
        self.data = b""
        self.size = 0
        self.kind = "unknown"
        self.file_cmd = None
        self.hashes = {}
        self.ssdeep = None
        self.entropy = 0.0
        self.windows = []
        self.pe = {}
        self.elf = {}
        self.dex = {}
        self.apk = {}
        self.ascii_strs = []
        self.wide_strs = []
        self.iocs = {}
        self.sigs = []
        self.caps = []
        self.carved = []
        self.yara = None
        self.vt = None
        self.bazaar = None
        self.pdb_rsds = []
        self.languages = []
        self.mtime = None
        self.disasm = []
        self.xor_keys = []
        self.xor_common = []
        self.stack_strings = []
        self.b64_decoded = []
        self.split_urls = []
        self.dga = []
        self.families = []
        self.tls = {}
        self.delay_imports = []
        self.exceptions = {}
        self.bound_imports = []
        self.resources = {}
        self.java = {}
        self.ole = {}
        self.ooxml = {}
        self.pdf = {}
        self.upx = {}
        self.oep_notes = []
        self.iat_notes = []
        self.warnings = []
        self.score = 0
        self.label = ""
        self.level = "info"
        self.reasons = []

    def load(self, max_mb=256):
        if not self.exists:
            raise FileNotFoundError(self.path)
        self.size = os.path.getsize(self.path)
        limit = int(max_mb * 1024 * 1024)
        if self.size > limit:
            self.warnings.append("file is %s; reading first %s only" % (human_size(self.size), human_size(limit)))
            self.data = read_file(self.path, limit)
        else:
            self.data = read_file(self.path)
        if not self.data:
            raise ValueError("empty file")

    def analyze(self, do_vt=False, do_yara=True, max_strings=6000):
        self.file_cmd = file_cmd(self.path)
        mag = identify_magic(self.data)
        if self.data.startswith(b"MZ"):
            self.kind = "pe"
        elif self.data.startswith(b"\x7fELF"):
            self.kind = "elf"
        elif self.data.startswith(b"dex\n"):
            self.kind = "dex"
        elif self.data.startswith(b"PK"):
            # APK vs generic zip
            self.kind = "zip"
        elif self.data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                               b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            self.kind = "macho"
        elif self.data[:4] == b"\xca\xfe\xba\xbe":
            self.kind = "class_or_fat"
        elif self.data.startswith(b"%PDF"):
            self.kind = "pdf"
        elif self.data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            self.kind = "ole"
        elif self.data[:2] == b"#!":
            self.kind = "script"

        self.hashes = all_hashes(self.data if self.size == len(self.data) else read_file(self.path))
        # if we truncated, rehash full file cheaply by streaming
        if self.size != len(self.data):
            self.hashes = stream_hashes(self.path)
        self.ssdeep = ssdeep_hash(self.path)
        self.entropy = shannon_entropy(self.data)
        self.windows = windowed_entropy(self.data, win=512, step=256)

        if self.kind == "pe" or self.data.startswith(b"MZ"):
            self.pe = parse_pe(self.data)
            if self.pe.get("valid"):
                self.kind = "pe"
        if self.kind == "elf" or self.data.startswith(b"\x7fELF"):
            self.elf = parse_elf(self.data)
            if self.elf.get("valid"):
                self.kind = "elf"
        if self.data.startswith(b"dex\n"):
            self.dex = parse_dex(self.data)
            self.kind = "dex"
        if self.data.startswith(b"PK"):
            self.apk = parse_apk(self.path, self.data)
            self.ooxml = parse_ooxml(self.data, self.path)
            if self.apk.get("has_manifest") or self.apk.get("dex"):
                self.kind = "apk"
            elif self.ooxml.get("is_office"):
                self.kind = "ooxml"
            else:
                self.kind = "zip"
        if self.data[:4] == b"\xca\xfe\xba\xbe":
            self.java = parse_java_class(self.data)
            if self.java.get("valid"):
                self.kind = "class"
        if self.data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            self.ole = parse_ole(self.data)
            if self.ole.get("valid"):
                self.kind = "ole"
        if self.data.startswith(b"%PDF"):
            self.pdf = parse_pdf(self.data)
            self.kind = "pdf"

        self.ascii_strs, self.wide_strs = extract_strings(self.data, min_len=5, max_strings=max_strings)
        self.iocs = harvest_iocs(self.data, self.ascii_strs, self.wide_strs)
        self.sigs = detect_signatures(self.data)
        extra = " ".join(self.apk.get("permissions") or [])
        imports = self.pe.get("imports") if self.pe else []
        self.caps = map_capabilities(imports, self.ascii_strs + self.wide_strs, extra)
        self.carved = carve_embedded(self.data, self.kind)
        self.pdb_rsds = find_pdb_rsds(self.data)
        self.languages = language_fingerprint(self.data, self.pe, self.sigs)
        # deeper static recovery
        try:
            arch = _arch_mode(self.pe, self.elf)
            origin = 0
            blob = b""
            if self.pe.get("valid"):
                off = _entry_file_off(self.pe)
                if off is not None:
                    blob = self.data[off:off + 256]
                    origin = self.pe.get("entry_rva") or 0
            elif self.elf.get("valid"):
                blob = self.data[0:64]
            if blob:
                self.disasm = disasm_bytes(blob, arch=arch, origin=origin, max_ins=32)
            self.xor_keys = xor_bruteforce(self.data)
            self.xor_common = xor_common_keys(self.data)
            self.stack_strings = recover_stack_strings(self.data)
            self.b64_decoded = decode_base64_blobs(self.data, self.ascii_strs)
            self.split_urls = reconstruct_split_urls(self.ascii_strs)
            self.dga = dga_like_domains(self.iocs.get("domains") or [])
            self.families = family_hints(self.data, self.ascii_strs, self.iocs)
            if self.pe.get("valid"):
                self.tls = parse_tls(self.data, self.pe)
                self.delay_imports = parse_delay_imports(self.data, self.pe)
                self.exceptions = parse_exceptions(self.data, self.pe)
                self.bound_imports = parse_bound_imports(self.data, self.pe)
                self.resources = parse_resources(self.data, self.pe)
                self.oep_notes = oep_heuristics(self.pe)
                self.iat_notes = iat_hints(self.data, self.pe)
            self.upx = upx_unpack(self.path, self.data)
        except Exception as e:
            self.warnings.append("deep analysis: %s" % e)
        try:
            self.mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(self.path), datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            self.mtime = None

        if do_yara:
            self.yara = yara_scan(self.path)
        if do_vt:
            self.vt = vt_lookup(self.hashes.get("sha256", ""))

        ctx = {
            "entropy": self.entropy,
            "pe": self.pe,
            "elf": self.elf,
            "apk": self.apk,
            "sigs": self.sigs,
            "caps": self.caps,
            "iocs": self.iocs,
            "carved": self.carved,
        }
        self.score, self.label, self.level, self.reasons = risk_score(ctx)
        extra_pts = 0
        if (self.tls or {}).get("callbacks"):
            extra_pts += 12
            self.reasons.append("TLS callbacks: " + ", ".join("0x%X" % c for c in self.tls["callbacks"][:6]))
        if self.delay_imports:
            extra_pts += 4
            self.reasons.append("delay-load imports: %s" % ", ".join(d.get("dll") or "?" for d in self.delay_imports[:6]))
        if self.families:
            extra_pts += 8
            self.reasons.append("family fingerprints: %s" % ", ".join(f["family"] for f in self.families))
        if self.pdf.get("js") or self.pdf.get("openaction"):
            extra_pts += 10
            self.reasons.append("PDF JavaScript / OpenAction")
        if self.ole.get("has_vba") or self.ooxml.get("has_macros"):
            extra_pts += 10
            self.reasons.append("Office macros / VBA project")
        if any(x.get("magic") for x in self.xor_keys):
            extra_pts += 14
            self.reasons.append("XOR key reveals an embedded executable header")
        if extra_pts:
            self.score = max(0, min(100, self.score + extra_pts))
            if self.score >= 70:
                self.label, self.level = "HOSTILE-LOOKING", "crit"
            elif self.score >= 45:
                self.label, self.level = "SUSPICIOUS", "high"
            elif self.score >= 25:
                self.label, self.level = "INTERESTING", "med"
            elif self.score >= 10:
                self.label, self.level = "WEAK SIGNALS", "low"
        self.warnings.extend(self.pe.get("warnings") or [])
        self.warnings.extend(self.elf.get("warnings") or [])
        self.warnings.extend(self.apk.get("warnings") or [])

    def print_overview(self):
        section("overview", "☠")
        kv("path", self.path, vcolor=C.ice)
        kv("size", "%s (%d bytes)" % (human_size(self.size), self.size))
        kv("kind", self.kind.upper(), vcolor=C.violet + C.bold)
        if self.file_cmd:
            kv("file(1)", self.file_cmd, vcolor=C.bone)
        kv("entropy", entropy_bar(self.entropy))
        cprint("  %s%-22s%s %s" % (C.ash, "entropy map", C.reset, ascii_heatmap(self.windows)))
        kv("md5", self.hashes.get("md5", ""))
        kv("sha1", self.hashes.get("sha1", ""))
        kv("sha256", self.hashes.get("sha256", ""), vcolor=C.gold)
        kv("sha512", (self.hashes.get("sha512", "")[:48] + "…") if self.hashes.get("sha512") else "")
        if self.ssdeep:
            kv("ssdeep", self.ssdeep, vcolor=C.teal)
        if self.hashes.get("crc32"):
            kv("crc32", self.hashes["crc32"])
        if self.hashes.get("blake2b"):
            kv("blake2b-256", self.hashes["blake2b"])
        if self.mtime:
            kv("mtime (fs)", self.mtime)
        if self.languages:
            kv("toolchain", ", ".join(self.languages), vcolor=C.violet)
        print()
        flag(self.level, "heuristic verdict  %s%s %s%d/100%s  %s" % (
            C.bold, self.label, C.reset + C.ash, self.score, C.reset, C.dim + "(not an AV detection)" + C.reset))
        if self.vt:
            if self.vt.get("error"):
                flag("note", "VirusTotal: %s" % self.vt["error"])
            else:
                flag("high" if self.vt.get("malicious", 0) else "info",
                     "VirusTotal  malicious=%s suspicious=%s undetected=%s  label=%s" % (
                         self.vt.get("malicious"), self.vt.get("suspicious"),
                         self.vt.get("undetected"), self.vt.get("label") or "-"))
        if self.bazaar:
            if self.bazaar.get("error"):
                flag("note", "MalwareBazaar: %s" % self.bazaar["error"])
            elif self.bazaar.get("query_status") == "ok":
                flag("high", "MalwareBazaar  hits=%s  family=%s  sig=%s" % (
                    self.bazaar.get("count", "?"),
                    self.bazaar.get("family") or "-",
                    self.bazaar.get("signature") or "-"))
            else:
                flag("info", "MalwareBazaar: %s" % (self.bazaar.get("query_status") or "no record"))

    def print_pe(self):
        pe = self.pe
        if not pe or not pe.get("valid"):
            if self.kind == "pe":
                section("pe", "🪟")
                flag("high", "MZ found but PE parse failed")
                for w in pe.get("warnings") or []:
                    flag("note", w)
            return
        section("portable executable", "🪟")
        kv("machine", pe["machine"])
        kv("type", "DLL" if pe.get("is_dll") else "EXE / image")
        kv("subsystem", pe.get("subsystem"))
        kv("magic", "PE32+" if pe.get("pe32plus") else "PE32")
        kv("image base", "0x%X" % pe["image_base"])
        kv("entry RVA", "0x%X" % pe["entry_rva"])
        kv("timestamp", "%s  (0x%X)" % (pe["compiled"], pe["timestamp"]))
        kv("OS version", pe.get("os"))
        kv("image size", human_size(pe.get("size_image") or 0))
        kv("overlay", human_size(pe.get("overlay") or 0) if pe.get("overlay") else "none",
           vcolor=C.amber if pe.get("overlay") else C.moss)
        kv("characteristics", ", ".join(pe.get("char_flags") or []) or "-")
        kv("dll chars", ", ".join(pe.get("dll_flags") or []) or "-")
        mitigations = []
        df = pe.get("dll_flags") or []
        mitigations.append("ASLR" if "DYNAMIC_BASE" in df else C.red + "NO ASLR" + C.reset)
        mitigations.append("NX" if "NX_COMPAT" in df else C.red + "NO NX" + C.reset)
        mitigations.append("CFG" if "GUARD_CF" in df else "no CFG")
        mitigations.append("high-entropy VA" if "HIGH_ENTROPY_VA" in df else "no HEVA")
        kv("mitigations", " · ".join(mitigations))
        ih = pe_imphash(pe.get("imports") or [])
        if ih:
            kv("imphash", ih, vcolor=C.teal)
        kv(".NET/CLR", "yes" if pe.get("is_dotnet") else "no",
           vcolor=C.amber if pe.get("is_dotnet") else C.ash)
        kv("Authenticode dir",
           ("yes  0x%X + %s" % (pe["cert_dir"][0], human_size(pe["cert_dir"][1])))
           if pe.get("has_signature") else "not advertised",
           vcolor=C.lime if pe.get("has_signature") else C.ash)
        rich = pe.get("rich") or {}
        if rich.get("present"):
            kv("Rich header", "%d entries  xor=%s  md5=%s" % (
                rich.get("n_entries", 0), rich.get("xor_key"), (rich.get("checksum") or "")[:16] + "…"),
                vcolor=C.teal)
        if self.pdb_rsds:
            for p in self.pdb_rsds[:4]:
                kv("RSDS PDB", "%s  (age %s @ 0x%X)" % (p["path"], p["age"], p["offset"]), vcolor=C.gold)

        print()
        cprint(C.violet + C.bold + "  sections" + C.reset)
        hdr = "  %-10s %10s %10s %10s %10s %s" % (
            "name", "vsize", "raw", "vaddr", "entropy", "flags")
        cprint(C.slate + hdr + C.reset)
        for s in pe.get("sections") or []:
            name = s["name"] or "??"
            col = C.bone
            if s["name"] in SUSPICIOUS_SECTIONS:
                col = C.red + C.bold
            elif "EXECUTE" in s["flags"] and "WRITE" in s["flags"]:
                col = C.rust
            elif s["entropy"] >= 7.2:
                col = C.amber
            cprint("  %s%-10s%s %10s %10s %10s %10.3f %s" % (
                col, name[:10], C.reset,
                "0x%X" % s["vsize"], "0x%X" % s["raw_size"],
                "0x%X" % s["vaddr"], s["entropy"],
                ",".join(s["flags"])[:40],
            ))

        imps = pe.get("imports") or []
        print()
        cprint(C.violet + C.bold + "  imports  (%d DLLs)" % len(imps) + C.reset)
        if not imps:
            flag("med", "no import table parsed — packed, delayed, or malformed")
        for imp in imps[:40]:
            funcs = imp.get("funcs") or []
            marked = []
            for f in funcs[:24]:
                if f in SUSPICIOUS_IMPORTS:
                    marked.append(C.red + f + C.reset)
                else:
                    marked.append(f)
            extra = "" if len(funcs) <= 24 else C.ash + " … +%d" % (len(funcs) - 24) + C.reset
            cprint("  %s%-22s%s %s%s" % (C.gold, (imp.get("dll") or "?")[:22], C.reset,
                                          ", ".join(marked), extra))

        exps = pe.get("exports") or []
        if exps:
            print()
            cprint(C.violet + C.bold + "  exports  (%d)" % len(exps) + C.reset)
            cprint("  " + ", ".join(exps[:40]) + (" …" if len(exps) > 40 else ""))

    def print_elf(self):
        elf = self.elf
        if not elf or not elf.get("valid"):
            return
        section("elf", "🐧")
        kv("class", elf.get("class"))
        kv("endian", elf.get("endian"))
        kv("type", elf.get("type"))
        kv("machine", elf.get("machine"))
        kv("OS ABI", elf.get("osabi"))
        kv("entry", "0x%X" % elf.get("entry", 0))
        kv("PHs / SHs", "%s / %s" % (elf.get("phnum"), elf.get("shnum")))
        kv("interpreter", elf.get("interp") or "-", vcolor=C.ice)
        if elf.get("needed"):
            kv("needed libs", ", ".join(elf["needed"][:20]))
        print()
        cprint(C.violet + C.bold + "  sections" + C.reset)
        cprint(C.slate + "  %-20s %10s %10s %8s" % ("name", "offset", "size", "entropy") + C.reset)
        for s in (elf.get("sections") or [])[:40]:
            col = C.amber if s["entropy"] >= 7.2 else C.bone
            cprint("  %s%-20s%s %10s %10s %8.3f" % (
                col, (s["name"] or "?")[:20], C.reset,
                "0x%X" % s["offset"], human_size(s["size"]), s["entropy"]))

    def print_android(self):
        if self.dex.get("valid"):
            section("dex", "🤖")
            d = self.dex
            kv("version", d.get("version"))
            kv("file size field", human_size(d.get("file_size") or 0))
            kv("endian", d.get("endian_tag"))
            kv("string_ids", d.get("string_ids"))
            kv("type_ids", d.get("type_ids"))
            kv("method_ids", d.get("method_ids"))
            kv("class_defs", d.get("class_defs"))
        apk = self.apk
        if not apk or not apk.get("valid"):
            return
        section("apk / zip package", "📦")
        kv("entries", apk.get("n_entries"))
        kv("AndroidManifest", "yes" if apk.get("has_manifest") else "no",
           vcolor=C.lime if apk.get("has_manifest") else C.amber)
        kv("resources.arsc", "yes" if apk.get("has_resources") else "no")
        if apk.get("dex"):
            print()
            cprint(C.violet + C.bold + "  DEX files" + C.reset)
            for d in apk["dex"]:
                cprint("  %s%-28s%s %8s  sha256=%s" % (
                    C.gold, d.get("name"), C.reset, human_size(d.get("size") or 0),
                    (d.get("sha256") or "")[:16] + "…"))
                if d.get("valid"):
                    kv("    classes / methods", "%s / %s" % (d.get("class_defs"), d.get("method_ids")), key_w=22)
        if apk.get("native"):
            print()
            cprint(C.violet + C.bold + "  native libs" + C.reset)
            for n in apk["native"][:30]:
                cprint("  " + C.ice + n + C.reset)
        if apk.get("certs"):
            print()
            cprint(C.violet + C.bold + "  signing crumbs" + C.reset)
            for n in apk["certs"]:
                cprint("  " + n)
        perms = apk.get("permissions") or []
        if perms:
            print()
            cprint(C.violet + C.bold + "  permissions harvested from package" + C.reset)
            for p in perms:
                if p in INTERESTING_PERMS:
                    flag("high", "android.permission." + p)
                else:
                    cprint("  " + C.ash + "android.permission." + p + C.reset)

    def print_sigs_caps(self):
        section("signatures & capabilities", "🧿")
        if self.sigs:
            for s in self.sigs:
                flag("note", s)
        else:
            flag("info", "no built-in packer/compiler signatures hit")
        print()
        if self.caps:
            for cap in self.caps:
                ev = ", ".join(cap["evidence"][:6])
                flag(cap["level"], "%s  %s(%s)%s" % (cap["name"], C.dim, ev, C.reset))
        else:
            flag("ok", "no high-signal capability patterns from imports/strings")
        if self.carved:
            print()
            cprint(C.violet + C.bold + "  embedded binaries" + C.reset)
            for c in self.carved:
                flag("med", "%s at offset 0x%X (%d)" % (c["kind"], c["offset"], c["offset"]))
        if self.yara:
            print()
            cprint(C.violet + C.bold + "  yara" + C.reset)
            if self.yara.get("note"):
                flag("info", self.yara["note"])
            if self.yara.get("hits"):
                for h in self.yara["hits"][:40]:
                    flag("high", h)
            elif self.yara.get("available") and not self.yara.get("note"):
                flag("ok", "no rule hits")

    def print_iocs(self):
        section("strings & IOCs", "📜")
        a, w = len(self.ascii_strs), len(self.wide_strs)
        kv("ascii strings", a)
        kv("utf-16le strings", w)
        kv("base64-like blobs", self.iocs.get("b64_blobs", 0))

        def show(title, items, color=C.ice, limit=20):
            if not items:
                return
            print()
            cprint(C.violet + C.bold + "  " + title + " (%d)" % len(items) + C.reset)
            for x in items[:limit]:
                cprint("    " + color + x + C.reset)
            if len(items) > limit:
                cprint(C.ash + "    … %d more" % (len(items) - limit) + C.reset)

        show("URLs", self.iocs.get("urls") or [], C.gold)
        show("domains", self.iocs.get("domains") or [], C.gold)
        show("IPv4", self.iocs.get("ips") or [], C.amber)
        show("emails", self.iocs.get("emails") or [], C.rose)
        show("registry", self.iocs.get("registry") or [], C.rust)
        show("paths (runtime-looking)", self.iocs.get("paths") or [], C.teal)
        show("build / source leftovers (not recoverable files)",
             self.iocs.get("build_paths") or [], C.ash)
        show("PDB strings", self.iocs.get("pdb") or [], C.gold)
        show("mutex-like", self.iocs.get("mutex") or [], C.grape)
        show("known-framework mutex names", self.iocs.get("mutex_framework") or [], C.ash)
        show(".onion", self.iocs.get("onions") or [], C.red)
        show("wallet-like", self.iocs.get("wallets") or [], C.amber)
        show("interesting strings", self.iocs.get("interesting") or [], C.bone, limit=30)

    def print_strings(self, n=80, filt=None):
        section("string dump", "🔤")
        pooled = self.ascii_strs + ["[wide] " + s for s in self.wide_strs]
        if filt:
            fl = filt.lower()
            pooled = [s for s in pooled if fl in s.lower()]
        for s in pooled[:n]:
            cprint("  " + C.bone + s[:240] + C.reset)
        cprint(C.ash + "  (%d shown, %d total after filter)" % (min(n, len(pooled)), len(pooled)) + C.reset)

    def print_hex(self, offset=0, length=256):
        section("hex dump", "⬡")
        cprint(hexdump(self.data, offset=offset, length=length))

    def print_hist(self):
        section("byte histogram", "▦")
        cprint(C.ash + "  each cell is a byte value 00..FF; taller = more common" + C.reset)
        cprint(print_histogram(self.data[: min(len(self.data), 8 * 1024 * 1024)]))

    def extract_artifacts(self, outdir):
        """Write overlay + carved blobs. Never executes them."""
        os.makedirs(outdir, exist_ok=True)
        written = []
        pe = self.pe or {}
        if pe.get("overlay"):
            # last raw end approximated by size - overlay
            start = max(0, len(self.data) - int(pe["overlay"]))
            blob = self.data[start:]
            dest = os.path.join(outdir, os.path.basename(self.path) + ".overlay.bin")
            with open(dest, "wb") as f:
                f.write(blob)
            written.append(dest)
        for i, c in enumerate(self.carved or []):
            dest = os.path.join(outdir, "%s.carved_%d_%s.bin" % (
                os.path.basename(self.path), i, c["kind"].lower()))
            with open(dest, "wb") as f:
                f.write(self.data[c["offset"]:c["offset"] + min(2_000_000, len(self.data) - c["offset"])])
            written.append(dest)
        return written

    def ioc_text(self):
        lines = ["# NECROBIN IOCs  %s" % self.hashes.get("sha256", ""),
                 "# %s" % self.path]
        mapping = [
            ("url", "urls"), ("domain", "domains"), ("ip", "ips"),
            ("email", "emails"), ("registry", "registry"),
            ("path", "paths"), ("pdb", "pdb"), ("mutex", "mutex"),
            ("onion", "onions"), ("wallet", "wallets"),
        ]
        for label, key in mapping:
            for v in self.iocs.get(key) or []:
                lines.append("%s\t%s" % (label, v))
        return "\n".join(lines) + "\n"

    def print_score(self):
        section("heuristic autopsy notes", "⚖")
        flag(self.level, "%s  (%d/100)" % (self.label, self.score))
        for r in self.reasons[:25]:
            cprint("    " + C.ash + "• " + C.reset + r)
        if self.warnings:
            print()
            for w in self.warnings:
                flag("note", w)
        print()
        cprint(C.dim + "  This score is a static heuristic for triage, not a verdict." + C.reset)
        cprint(C.dim + "  Packed clean software and packed malware both look noisy. Do not execute samples." + C.reset)

    def print_deep(self):
        section("code & crypto recovery", "⚗")
        if self.disasm:
            src = self.disasm[0].get("src")
            cprint(C.violet + C.bold + "  entry disassembly (%s)" % src + C.reset)
            for ins in self.disasm[:24]:
                note = ins["text"]
                if ins.get("src") == "raw" and ins != self.disasm[0]:
                    continue
                cprint("    %s%08x%s  %s%-16s%s %s" % (
                    C.slate, ins["addr"], C.reset, C.ice, ins["hex"][:16], C.reset, note))
        else:
            flag("info", "no entry bytes to disassemble")
        if self.oep_notes:
            print()
            for n in self.oep_notes:
                flag("note", n)
        if self.iat_notes:
            for n in self.iat_notes:
                flag("info", n)
        if self.tls:
            print()
            cprint(C.violet + C.bold + "  TLS" + C.reset)
            if self.tls.get("callbacks"):
                flag("high", "callbacks: " + ", ".join("0x%X" % c for c in self.tls["callbacks"]))
            elif self.tls.get("present"):
                flag("info", "TLS directory present, no callback RVAs parsed")
            if self.tls.get("note"):
                flag("note", self.tls["note"])
        if self.delay_imports:
            print()
            cprint(C.violet + C.bold + "  delay-load imports" + C.reset)
            for d in self.delay_imports[:20]:
                cprint("    " + C.gold + (d.get("dll") or "?") + C.reset)
        if self.exceptions.get("present"):
            flag("info", "exception dir  RVA=0x%X size=%s entries≈%s" % (
                self.exceptions.get("rva", 0), human_size(self.exceptions.get("size") or 0),
                self.exceptions.get("count")))
        if self.bound_imports:
            flag("info", "bound imports: " + ", ".join(self.bound_imports[:12]))
        res = self.resources or {}
        if res.get("present"):
            print()
            cprint(C.violet + C.bold + "  resources" + C.reset)
            kv("types", ", ".join("%s×%s" % (k, v) for k, v in (res.get("summary") or {}).items()))
            kv("RCDATA blobs", res.get("rcdata", 0), vcolor=C.amber if res.get("rcdata") else C.ash)
            for k, v in (res.get("version") or {}).items():
                kv(k, v)
            if res.get("manifest_preview"):
                cprint(C.ash + "    manifest: " + res["manifest_preview"][:180].replace("\n", " ") + C.reset)
        if self.upx:
            print()
            cprint(C.violet + C.bold + "  UPX" + C.reset)
            if self.upx.get("unpacked"):
                flag("ok", "decompressed → %s (%s)" % (self.upx["unpacked"], human_size(self.upx.get("unpacked_size") or 0)))
            elif self.upx.get("packed"):
                flag("med", self.upx.get("error") or "packed, not unpacked")
        if self.xor_keys:
            print()
            cprint(C.violet + C.bold + "  XOR brute-force (top keys)" + C.reset)
            for item in self.xor_keys[:5]:
                flag("med" if item.get("magic") else "info",
                     "key %s score=%s%s" % (item["key_hex"], item["score"],
                                            "  " + item["magic"] if item.get("magic") else ""))
                for s in item.get("strings") or [][:4]:
                    cprint("      " + C.bone + s[:160] + C.reset)
        if self.xor_common:
            print()
            cprint(C.violet + C.bold + "  common XOR / padding" + C.reset)
            for item in self.xor_common[:4]:
                cprint("    key %s" % item["key"])
                for s in item.get("strings") or [][:3]:
                    cprint("      " + C.ash + s[:160] + C.reset)
        if self.stack_strings:
            print()
            cprint(C.violet + C.bold + "  reconstructed stack strings" + C.reset)
            for s in self.stack_strings[:20]:
                cprint("    " + C.gold + s[:180] + C.reset)
        if self.b64_decoded:
            print()
            cprint(C.violet + C.bold + "  base64 decoded" + C.reset)
            for b in self.b64_decoded[:12]:
                flag("high" if b["kind"] in ("PE", "ELF", "DEX") else "info",
                     "%s  %s B  %s  %s" % (b["kind"], b["decoded_len"], b["preview"], b.get("text") or ""))
                for u in b.get("urls") or []:
                    cprint("      " + C.gold + u + C.reset)
        if self.split_urls:
            print()
            cprint(C.violet + C.bold + "  reconstructed / defanged URLs" + C.reset)
            for u in self.split_urls:
                cprint("    " + C.gold + u + C.reset)
        if self.dga:
            print()
            cprint(C.violet + C.bold + "  DGA-looking domains" + C.reset)
            for d in self.dga:
                flag("med", "%s  H=%.2f vowels=%.2f" % (d["domain"], d["entropy"], d["vowel_ratio"]))
        if self.families:
            print()
            cprint(C.violet + C.bold + "  family fingerprints" + C.reset)
            for f in self.families:
                flag("high", "%s  (%s) — %s" % (f["family"], ", ".join(f["evidence"]), f["note"]))

    def print_docs(self):
        if self.java.get("valid"):
            section("java class", "☕")
            kv("version", "%s.%s" % (self.java.get("major"), self.java.get("minor")))
            for s in (self.java.get("interesting") or self.java.get("cp_strings") or [])[:30]:
                cprint("    " + C.bone + s[:180] + C.reset)
        if self.ole.get("valid"):
            section("ole compound", "📄")
            kv("guess", self.ole.get("kind_guess"))
            kv("VBA", "yes" if self.ole.get("has_vba") else "no",
               vcolor=C.red if self.ole.get("has_vba") else C.ash)
            for n in self.ole.get("streams") or []:
                cprint("    " + C.ice + n + C.reset)
        if self.ooxml.get("valid") and (self.ooxml.get("is_office") or self.kind == "ooxml"):
            section("office ooxml", "📄")
            kv("type", self.ooxml.get("content_types"))
            kv("macros", "yes" if self.ooxml.get("has_macros") else "no",
               vcolor=C.red if self.ooxml.get("has_macros") else C.ash)
            for n in self.ooxml.get("macros") or []:
                cprint("    " + C.amber + n + C.reset)
        if self.pdf.get("valid"):
            section("pdf", "📕")
            kv("streams", self.pdf.get("streams"))
            kv("/JavaScript", "yes" if self.pdf.get("js") else "no",
               vcolor=C.red if self.pdf.get("js") else C.ash)
            kv("/OpenAction", "yes" if self.pdf.get("openaction") else "no")
            kv("/EmbeddedFile", "yes" if self.pdf.get("embedded") else "no")
            for u in self.pdf.get("uris") or []:
                cprint("    URI " + C.gold + u + C.reset)
            for s in self.pdf.get("js_snippets") or []:
                cprint("    JS  " + C.amber + s[:180] + C.reset)

    def print_full(self, strings_n=0):
        self.print_overview()
        self.print_pe()
        self.print_elf()
        self.print_android()
        self.print_docs()
        self.print_sigs_caps()
        self.print_deep()
        self.print_iocs()
        if strings_n:
            self.print_strings(n=strings_n)
        self.print_hex(0, 128)
        self.print_hist()
        self.print_score()

    def to_text_report(self):
        # colorless-ish report via capturing would be hard; build manually
        buf = io.StringIO()
        W = buf.write
        W("NECROBIN autopsy report v%s\n" % VERSION)
        W("generated %s\n" % utc_dt().strftime("%Y-%m-%d %H:%M:%S UTC"))
        W("path: %s\n" % self.path)
        W("size: %d\n" % self.size)
        W("kind: %s\n" % self.kind)
        W("file(1): %s\n" % (self.file_cmd or ""))
        W("entropy: %.4f\n" % self.entropy)
        W("mtime: %s\n" % (self.mtime or ""))
        W("toolchain: %s\n" % ", ".join(self.languages or []))
        for k, v in self.hashes.items():
            W("%s: %s\n" % (k, v))
        if self.ssdeep:
            W("ssdeep: %s\n" % self.ssdeep)
        W("verdict: %s (%d/100)\n" % (self.label, self.score))
        for r in self.reasons:
            W("  - %s\n" % r)
        if self.pe.get("valid"):
            W("\n[PE]\n")
            W("machine=%s subsystem=%s ts=%s entry=0x%X base=0x%X overlay=%d\n" % (
                self.pe.get("machine"), self.pe.get("subsystem"), self.pe.get("compiled"),
                self.pe.get("entry_rva", 0), self.pe.get("image_base", 0), self.pe.get("overlay", 0)))
            W("chars: %s\n" % ", ".join(self.pe.get("char_flags") or []))
            W("dll: %s\n" % ", ".join(self.pe.get("dll_flags") or []))
            ih = pe_imphash(self.pe.get("imports") or [])
            if ih:
                W("imphash: %s\n" % ih)
            for s in self.pe.get("sections") or []:
                W("  sect %-8s vsz=0x%X raw=0x%X va=0x%X ent=%.3f %s\n" % (
                    s["name"], s["vsize"], s["raw_size"], s["vaddr"], s["entropy"],
                    ",".join(s["flags"])))
            for imp in self.pe.get("imports") or []:
                W("  import %s: %s\n" % (imp.get("dll"), ", ".join(imp.get("funcs") or [])[:500]))
            if self.pe.get("exports"):
                W("  exports: %s\n" % ", ".join(self.pe["exports"][:100]))
        if self.elf.get("valid"):
            W("\n[ELF]\n")
            W("%s %s %s %s entry=0x%X interp=%s\n" % (
                self.elf.get("class"), self.elf.get("type"), self.elf.get("machine"),
                self.elf.get("osabi"), self.elf.get("entry", 0), self.elf.get("interp")))
            W("needed: %s\n" % ", ".join(self.elf.get("needed") or []))
        if self.apk.get("valid"):
            W("\n[APK]\n")
            W("entries=%s manifest=%s\n" % (self.apk.get("n_entries"), self.apk.get("has_manifest")))
            W("perms: %s\n" % ", ".join(self.apk.get("permissions") or []))
            W("native: %s\n" % ", ".join(self.apk.get("native") or []))
            for d in self.apk.get("dex") or []:
                W("  dex %s size=%s sha256=%s classes=%s\n" % (
                    d.get("name"), d.get("size"), d.get("sha256"), d.get("class_defs")))
        W("\n[signatures]\n")
        for s in self.sigs:
            W("  %s\n" % s)
        W("\n[capabilities]\n")
        for c in self.caps:
            W("  %s (%s) evidence=%s\n" % (c["name"], c["level"], ",".join(c["evidence"])))
        W("\n[IOCs]\n")
        for k in ("urls", "domains", "ips", "emails", "registry", "paths",
                  "build_paths", "pdb", "mutex", "mutex_framework", "onions",
                  "wallets", "interesting"):
            for x in self.iocs.get(k) or []:
                W("  %s: %s\n" % (k, x))
        if self.pdb_rsds:
            W("\n[rsds]\n")
            for p in self.pdb_rsds:
                W("  %s\n" % p)
        if self.carved:
            W("\n[carved]\n")
            for c in self.carved:
                W("  %s @ 0x%X\n" % (c["kind"], c["offset"]))
        if self.yara and self.yara.get("hits"):
            W("\n[yara]\n")
            for h in self.yara["hits"]:
                W("  %s\n" % h)
        W("\n[warnings]\n")
        for w in self.warnings:
            W("  %s\n" % w)
        W("\n[tls]\n%s\n" % self.tls)
        W("[delay_imports] %s\n" % self.delay_imports)
        W("[families] %s\n" % self.families)
        W("[xor_keys] %s\n" % [
            dict([(k, v) for k, v in x.items() if k != "strings"] + [("n_strings", len(x.get("strings") or []))])
            for x in (self.xor_keys or [])
        ])
        W("[stack_strings]\n")
        for s in self.stack_strings or []:
            W("  %s\n" % s)
        W("[split_urls]\n")
        for s in self.split_urls or []:
            W("  %s\n" % s)
        return buf.getvalue()

    def to_json(self):
        return {
            "tool": NAME,
            "version": VERSION,
            "path": self.path,
            "size": self.size,
            "kind": self.kind,
            "file_cmd": self.file_cmd,
            "hashes": self.hashes,
            "ssdeep": self.ssdeep,
            "entropy": self.entropy,
            "verdict": {"score": self.score, "label": self.label, "reasons": self.reasons},
            "pe": self.pe,
            "elf": self.elf,
            "dex": self.dex,
            "apk": self.apk,
            "signatures": self.sigs,
            "capabilities": self.caps,
            "iocs": self.iocs,
            "carved": self.carved,
            "yara": self.yara,
            "vt": self.vt,
            "bazaar": self.bazaar,
            "languages": self.languages,
            "pdb_rsds": self.pdb_rsds,
            "mtime": self.mtime,
            "warnings": self.warnings,
            "disasm": self.disasm,
            "xor_keys": self.xor_keys,
            "stack_strings": self.stack_strings,
            "b64_decoded": self.b64_decoded,
            "split_urls": self.split_urls,
            "dga": self.dga,
            "families": self.families,
            "tls": self.tls,
            "delay_imports": self.delay_imports,
            "exceptions": self.exceptions,
            "bound_imports": self.bound_imports,
            "resources": {k: v for k, v in (self.resources or {}).items() if k != "entries"} if self.resources else {},
            "java": self.java,
            "ole": self.ole,
            "ooxml": self.ooxml,
            "pdf": self.pdf,
            "upx": self.upx,
            "oep_notes": self.oep_notes,
            "strings_ascii_sample": self.ascii_strs[:200],
            "strings_wide_sample": self.wide_strs[:200],
        }

    def to_html(self):
        def esc(s):
            return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        parts = [
            "<!DOCTYPE html><html><head><meta charset=utf-8><title>NECROBIN %s</title>" % esc(os.path.basename(self.path)),
            "<style>body{background:#111;color:#ddd;font:14px/1.45 monospace;margin:24px}"
            "h1{color:#e74c3c}h2{color:#f1c40f;cursor:pointer}"
            "details{border:1px solid #333;margin:8px 0;padding:8px}"
            "summary{color:#9b59b6;cursor:pointer} .k{color:#888} .v{color:#ecf0f1}"
            "pre{white-space:pre-wrap}.crit{color:#e74c3c}.ok{color:#2ecc71}</style></head><body>",
            "<h1>NECROBIN %s</h1><p>%s &mdash; %s &mdash; %s/100</p>" % (
                VERSION, esc(self.path), esc(self.label), self.score),
            "<p>sha256 <span class=v>%s</span></p>" % esc(self.hashes.get("sha256")),
        ]
        blocks = [
            ("Overview", "kind %s  size %s  entropy %.3f  toolchain %s" % (
                self.kind, human_size(self.size), self.entropy, ", ".join(self.languages or []))),
            ("Reasons", "\n".join(self.reasons or [])),
            ("IOCs", "\n".join("%s\t%s" % (k, v) for k in ("urls", "domains", "ips", "emails", "mutex")
                               for v in (self.iocs.get(k) or []))),
            ("Stack strings", "\n".join(self.stack_strings or [])),
            ("XOR", json.dumps(self.xor_keys, default=str)[:4000]),
            ("Disasm", "\n".join("%08x  %s  %s" % (i["addr"], i["hex"], i["text"]) for i in (self.disasm or []))),
            ("Families", json.dumps(self.families, default=str)),
            ("PE resources", json.dumps((self.resources or {}).get("version"), default=str)),
            ("Warnings", "\n".join(self.warnings or [])),
        ]
        for title, body in blocks:
            parts.append("<details open><summary>%s</summary><pre>%s</pre></details>" % (esc(title), esc(body)))
        parts.append("</body></html>")
        return "\n".join(parts)

    def to_sarif(self):
        results = []
        for r in self.reasons or []:
            results.append({
                "ruleId": "necrobin.heuristic",
                "level": "warning" if self.score >= 25 else "note",
                "message": {"text": r},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": self.path}}}],
            })
        for cap in self.caps or []:
            results.append({
                "ruleId": "necrobin.capability." + cap["name"].split()[0],
                "level": "error" if cap["level"] in ("high", "crit") else "warning",
                "message": {"text": "%s (%s)" % (cap["name"], ", ".join(cap.get("evidence") or []))},
            })
        for h in (self.yara or {}).get("hits") or []:
            results.append({"ruleId": "yara", "level": "error", "message": {"text": h}})
        return json.dumps({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": NAME, "version": VERSION, "informationUri": "https://local/necrobin"}},
                "results": results,
            }],
        }, indent=2)

    def to_stix2(self):
        now = utc_dt().strftime("%Y-%m-%dT%H:%M:%SZ")
        objs = [{
            "type": "file",
            "spec_version": "2.1",
            "id": "file--%s" % self.hashes.get("md5", "0"),
            "hashes": {k.upper(): v for k, v in (self.hashes or {}).items() if k in ("md5", "sha1", "sha256")},
            "name": os.path.basename(self.path),
            "size": self.size,
        }]
        for i, url in enumerate((self.iocs or {}).get("urls") or [][:30]):
            objs.append({"type": "url", "spec_version": "2.1", "id": "url--%s-%d" % (self.hashes.get("md5", "x")[:8], i), "value": url})
        for i, ip in enumerate((self.iocs or {}).get("ips") or [][:30]):
            objs.append({"type": "ipv4-addr", "spec_version": "2.1", "id": "ipv4-addr--%s-%d" % (self.hashes.get("md5", "x")[:8], i), "value": ip})
        for i, d in enumerate((self.iocs or {}).get("domains") or [][:30]):
            objs.append({"type": "domain-name", "spec_version": "2.1", "id": "domain-name--%s-%d" % (self.hashes.get("md5", "x")[:8], i), "value": d})
        return json.dumps({"type": "bundle", "id": "bundle--%s" % self.hashes.get("sha256", "x")[:32],
                           "objects": objs}, indent=2)

    def to_misp(self):
        attrs = []
        mapping = [("sha256", "sha256", self.hashes.get("sha256")),
                   ("md5", "md5", self.hashes.get("md5")),
                   ("filename", "filename", os.path.basename(self.path))]
        for t, _k, v in mapping:
            if v:
                attrs.append({"type": t, "value": v, "to_ids": True})
        for typ, key in (("url", "urls"), ("ip-dst", "ips"), ("domain", "domains"),
                         ("email-dst", "emails"), ("mutex", "mutex"), ("regkey", "registry")):
            for v in (self.iocs.get(key) or [])[:40]:
                attrs.append({"type": typ, "value": v, "to_ids": True})
        return json.dumps({
            "Event": {
                "info": "NECROBIN %s" % os.path.basename(self.path),
                "threat_level_id": "3" if self.score >= 45 else "4",
                "Attribute": attrs,
            }
        }, indent=2)



def stream_hashes(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    crc = 0
    b2 = hashlib.blake2b(digest_size=32) if hasattr(hashlib, "blake2b") else None
    s3 = hashlib.sha3_256() if hasattr(hashlib, "sha3_256") else None
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
            crc = zlib.crc32(chunk, crc)
            if b2:
                b2.update(chunk)
            if s3:
                s3.update(chunk)
    out = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
        "crc32": "%08x" % (crc & 0xFFFFFFFF),
    }
    if b2:
        out["blake2b"] = b2.hexdigest()
    if s3:
        out["sha3_256"] = s3.hexdigest()
    return out


# fix the dummy comment in to_json - I'll clean that when editing

# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

def compare_files(a_path, b_path):
    A = Autopsy(a_path)
    B = Autopsy(b_path)
    A.load()
    B.load()
    A.analyze(do_vt=False)
    B.analyze(do_vt=False)
    section("compare", "⚖")
    kv("A", A.path, vcolor=C.ice)
    kv("B", B.path, vcolor=C.gold)
    print()
    rows = [
        ("size", human_size(A.size), human_size(B.size), A.size == B.size),
        ("kind", A.kind, B.kind, A.kind == B.kind),
        ("md5", A.hashes["md5"][:16] + "…", B.hashes["md5"][:16] + "…", A.hashes["md5"] == B.hashes["md5"]),
        ("sha256", A.hashes["sha256"][:16] + "…", B.hashes["sha256"][:16] + "…", A.hashes["sha256"] == B.hashes["sha256"]),
        ("entropy", "%.3f" % A.entropy, "%.3f" % B.entropy, abs(A.entropy - B.entropy) < 0.05),
        ("verdict", "%s %d" % (A.label, A.score), "%s %d" % (B.label, B.score), A.label == B.label),
    ]
    cprint("  %-10s %-28s %-28s %s" % ("field", "A", "B", "match"))
    for field, av, bv, ok in rows:
        col = C.lime if ok else C.red
        cprint("  %-10s %-28s %-28s %s%s%s" % (field, av[:28], bv[:28], col, "YES" if ok else "NO", C.reset))

    # byte identity
    same = A.data == B.data if len(A.data) == len(B.data) else False
    flag("ok" if same else "med", "byte-identical (in analyzed window): %s" % same)

    # histogram distance
    def hist(d):
        h = [0] * 256
        for b in d:
            h[b] += 1
        return h

    if A.data and B.data:
        ha, hb = hist(A.data), hist(B.data)
        # cosine similarity
        dot = sum(x * y for x, y in zip(ha, hb))
        na = math.sqrt(sum(x * x for x in ha)) or 1.0
        nb = math.sqrt(sum(x * x for x in hb)) or 1.0
        cos = dot / (na * nb)
        kv("byte-hist cosine", "%.4f" % cos, vcolor=C.gold if cos > 0.95 else C.amber)
    ia = pe_imphash((A.pe or {}).get("imports") or [])
    ib = pe_imphash((B.pe or {}).get("imports") or [])
    if ia or ib:
        kv("imphash A", ia or "-")
        kv("imphash B", ib or "-")
        flag("ok" if ia and ia == ib else "info", "imphash match: %s" % (ia == ib and bool(ia)))
    return A, B


def scan_directory(root, do_vt=False, do_bazaar=False, do_yara=True):
    section("directory scan", "📁")
    kv("root", os.path.abspath(root), vcolor=C.ice)
    rows = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            try:
                if os.path.getsize(path) == 0:
                    continue
                s = Autopsy(path)
                s.load()
                s.analyze(do_vt=do_vt, do_yara=do_yara)
                if do_bazaar:
                    s.bazaar = bazaar_lookup(s.hashes.get("sha256", ""))
                rows.append(s)
            except Exception as e:
                flag("note", "%s: %s" % (path, e))
    rows.sort(key=lambda x: -x.score)
    print()
    cprint(C.slate + "  %-6s %-22s %8s %6s  %s" % ("score", "kind", "size", "ent", "file") + C.reset)
    for s in rows:
        col = {"crit": C.red, "high": C.rust, "med": C.amber, "low": C.moss, "ok": C.lime}.get(s.level, C.bone)
        rel = os.path.relpath(s.path, root)
        extra = ""
        if s.bazaar and s.bazaar.get("query_status") == "ok":
            extra = C.red + "  bazaar=" + (s.bazaar.get("family") or "hit") + C.reset
        cprint("  %s%5d%s  %-22s %8s %6.2f  %s%s" % (
            col, s.score, C.reset, (s.kind + "/" + s.label)[:22],
            human_size(s.size), s.entropy, rel, extra))
    flag("info", "%d file(s) scored. Higher is only a static heuristic." % len(rows))
    return 0


# ---------------------------------------------------------------------------
# Interactive
# ---------------------------------------------------------------------------

HELP_MENU = """
  {h}1{r}  full autopsy              {h}8{r}  hex dump
  {h}2{r}  overview / hashes         {h}9{r}  search strings
  {h}3{r}  format parser             {h}d{r}  disasm / XOR / stack / PE dirs
  {h}4{r}  signatures + caps         {h}g{r}  byte histogram
  {h}5{r}  IOCs                      {h}x{r}  extract overlay / carved
  {h}6{r}  interesting strings       {h}e{r}  export IOC / STIX / MISP / SARIF / HTML
  {h}7{r}  string dump               {h}y{r}  yara
  {h}v{r}  VirusTotal hash           {h}b{r}  MalwareBazaar hash
  {h}s{r}  save text report          {h}j{r}  save JSON
  {h}c{r}  compare                   {h}o{r}  open other sample
  {h}q{r}  quit
""".format(h=C.gold + C.bold, r=C.reset)


def prompt(msg):
    try:
        return input(C.gold + "  ▸ " + C.reset + C.bone + msg + C.reset)
    except EOFError:
        return "q"
    except KeyboardInterrupt:
        print()
        return "q"


def interactive(path, do_vt=False):
    banner()
    flag("info", "STATIC ONLY. This tool never runs the sample.")
    flag("info", "Keep samples isolated. Do not execute what you triage.")
    current = path
    sample = None

    def load_current():
        nonlocal sample
        sample = Autopsy(current)
        sample.load()
        sample.analyze(do_vt=do_vt)
        flag("ok", "loaded %s (%s, %s)" % (os.path.basename(current), sample.kind, human_size(sample.size)))

    load_current()
    sample.print_overview()
    while True:
        print()
        rule("·", 78, C.slate)
        cprint(C.ash + "  sample: " + C.ice + current + C.reset)
        cprint(HELP_MENU)
        choice = prompt("necrobin> ").strip().lower()
        if choice in ("q", "quit", "exit"):
            cprint(C.ash + "  buried. stay curious, stay careful." + C.reset)
            break
        elif choice in ("1", "full"):
            sample.print_full()
        elif choice in ("2", "ov"):
            sample.print_overview()
        elif choice in ("3", "pe", "elf"):
            sample.print_pe()
            sample.print_elf()
            sample.print_android()
            sample.print_docs()
        elif choice in ("d", "deep", "xor", "disasm"):
            sample.print_deep()
        elif choice in ("4", "cap"):
            sample.print_sigs_caps()
        elif choice in ("5", "ioc"):
            sample.print_iocs()
        elif choice in ("6",):
            sample.print_iocs()
        elif choice in ("7", "str"):
            n = prompt("how many [80]: ").strip() or "80"
            try:
                n = int(n)
            except ValueError:
                n = 80
            sample.print_strings(n=n)
        elif choice in ("8", "hex"):
            off = prompt("offset (0x.. or dec) [0]: ").strip() or "0"
            ln = prompt("length [256]: ").strip() or "256"
            try:
                off = int(off, 0)
                ln = int(ln, 0)
            except ValueError:
                off, ln = 0, 256
            sample.print_hex(off, ln)
        elif choice in ("9", "/", "search"):
            q = prompt("substring: ").strip()
            if q:
                sample.print_strings(n=200, filt=q)
        elif choice == "y":
            sample.yara = yara_scan(sample.path)
            sample.print_sigs_caps()
        elif choice == "v":
            sample.vt = vt_lookup(sample.hashes.get("sha256", ""))
            if not sample.vt:
                flag("note", "set NECROBIN_VT_KEY or VT_API_KEY to enable hash lookup (sends only SHA256)")
            sample.print_overview()
        elif choice == "s":
            out = prompt("write report to [./%s.necrobin.txt]: " % os.path.basename(current)).strip()
            if not out:
                out = "./%s.necrobin.txt" % os.path.basename(current)
            with open(out, "w", encoding="utf-8") as f:
                f.write(sample.to_text_report())
            flag("ok", "wrote " + out)
        elif choice == "j":
            out = prompt("write JSON to [./%s.necrobin.json]: " % os.path.basename(current)).strip()
            if not out:
                out = "./%s.necrobin.json" % os.path.basename(current)
            with open(out, "w", encoding="utf-8") as f:
                json.dump(sample.to_json(), f, indent=2, default=str)
            flag("ok", "wrote " + out)
        elif choice == "c":
            other = prompt("path to other sample: ").strip()
            if other and os.path.isfile(other):
                compare_files(current, other)
            else:
                flag("high", "no such file")
        elif choice == "o":
            nxt = prompt("path: ").strip()
            if nxt and os.path.isfile(nxt):
                current = nxt
                load_current()
                sample.print_overview()
            else:
                flag("high", "no such file")
        elif choice in ("g", "hist", "histogram"):
            sample.print_hist()
        elif choice in ("x", "extract"):
            dest = prompt("output directory [./necrobin_extract]: ").strip() or "./necrobin_extract"
            written = sample.extract_artifacts(dest)
            if written:
                for w in written:
                    flag("ok", "wrote " + w)
            else:
                flag("info", "nothing to extract (no overlay / carved blobs)")
        elif choice in ("e", "iocs"):
            kind = (prompt("format tsv/stix/misp/sarif/html [tsv]: ").strip() or "tsv").lower()
            ext = {"tsv": ".iocs.txt", "stix": ".stix.json", "misp": ".misp.json",
                   "sarif": ".sarif.json", "html": ".html"}.get(kind, ".iocs.txt")
            dest = prompt("path [./%s%s]: " % (os.path.basename(current), ext)).strip()
            if not dest:
                dest = "./%s%s" % (os.path.basename(current), ext)
            payload = {
                "tsv": sample.ioc_text,
                "stix": sample.to_stix2,
                "misp": sample.to_misp,
                "sarif": sample.to_sarif,
                "html": sample.to_html,
            }.get(kind, sample.ioc_text)()
            with open(dest, "w", encoding="utf-8") as f:
                f.write(payload)
            flag("ok", "wrote " + dest)
        elif choice == "b":
            sample.bazaar = bazaar_lookup(sample.hashes.get("sha256", ""))
            sample.print_overview()
        elif choice in ("h", "help", "?"):
            pass
        elif not choice:
            continue
        else:
            flag("note", "unknown command")


# ---------------------------------------------------------------------------
# Self test / demo on itself
# ---------------------------------------------------------------------------

def print_lab_tips():
    section("notes", "🧪")
    tips = [
        "STATIC ONLY. NECROBIN reads bytes and never executes the sample.",
        "Keep samples isolated. Strip execute bits:  chmod a-x samples/*",
        "Optional helpers (auto-detected): file, binutils, unzip, yara, ssdeep, curl",
        "Starter YARA rules: python3 necrobin.py --write-yara",
        "Custom rules: ~/.necrobin/rules.yar  or  NECROBIN_YARA=/path/rules.yar",
        "VirusTotal hash lookup: export NECROBIN_VT_KEY=...   (SHA256 only, no upload)",
        "MalwareBazaar hash lookup: --bazaar   (SHA256 only, no upload)",
        "Colors off: NO_COLOR=1    Colors in pipes: FORCE_COLOR=1",
        "Directory triage: python3 necrobin.py --scan ./samples",
        "Extract overlay / embedded PE-ELF-DEX: --extract-dir ./out",
        "IOC dump: --iocs sample.bin -o iocs.txt",
        "Do not upload live malware to random websites.",
    ]
    for t in tips:
        cprint("  " + C.ash + "• " + C.reset + C.bone + t + C.reset)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="necrobin",
        description="NECROBIN — static-only malware binary autopsy for the terminal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python3 necrobin.py payload.exe
  python3 necrobin.py -i dropper.apk
  python3 necrobin.py --compare v1.bin v2.bin
  python3 necrobin.py --report sample.so -o autopsy.txt
  python3 necrobin.py sample.dll --strings 200 --hex 0x400:128
  python3 necrobin.py --scan ./samples
  python3 necrobin.py --iocs sample.bin -o iocs.txt
  python3 necrobin.py --extract-dir ./out sample.bin
  python3 necrobin.py --write-yara
  NECROBIN_VT_KEY=xxx python3 necrobin.py --vt sample.bin
""",
    )
    p.add_argument("sample", nargs="?", help="path to the binary (or directory with --scan)")
    p.add_argument("other", nargs="?", help="second path (used with --compare)")
    p.add_argument("-i", "--interactive", action="store_true", help="interactive menu")
    p.add_argument("--compare", action="store_true", help="compare two samples")
    p.add_argument("--report", action="store_true", help="write a colorless text report")
    p.add_argument("--json", action="store_true", help="write JSON")
    p.add_argument("--html", action="store_true", help="write an HTML report")
    p.add_argument("--sarif", action="store_true", help="write SARIF 2.1")
    p.add_argument("--stix", action="store_true", help="write a STIX 2.1 bundle")
    p.add_argument("--misp", action="store_true", help="write MISP-like JSON")
    p.add_argument("-o", "--output", help="output path for reports ('-' = stdout)")
    p.add_argument("--strings", type=int, default=0, metavar="N", help="include N strings in the dump")
    p.add_argument("--hex", default=None, help="hex dump as OFFSET:LENGTH (e.g. 0:256 or 0x200:64)")
    p.add_argument("--vt", action="store_true", help="query VirusTotal by SHA256 (needs API key env)")
    p.add_argument("--bazaar", action="store_true", help="query MalwareBazaar by SHA256 (no API key)")
    p.add_argument("--scan", metavar="DIR", help="triage every regular file in a directory")
    p.add_argument("--iocs", action="store_true", help="export harvested IOCs as TSV")
    p.add_argument("--extract-dir", metavar="DIR", help="write overlay and carved blobs to DIR")
    p.add_argument("--write-yara", action="store_true", help="write starter rules to ~/.necrobin/rules.yar")
    p.add_argument("--no-yara", action="store_true", help="skip yara even if installed")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--tips", action="store_true", help="print usage notes and exit")
    p.add_argument("--version", action="store_true")
    return p


def parse_hex_arg(s):
    if not s:
        return 0, 256
    if ":" in s:
        a, b = s.split(":", 1)
        return int(a, 0), int(b, 0)
    return int(s, 0), 256


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(argv)

    if args.version:
        print("%s %s" % (NAME, VERSION))
        return 0
    if args.write_yara:
        path, created = write_starter_yara()
        if created:
            print("wrote " + path)
        else:
            print("already exists: " + path)
        return 0
    if args.tips:
        banner()
        print_lab_tips()
        return 0

    scan_dir = args.scan
    if args.sample and os.path.isdir(args.sample) and not scan_dir:
        scan_dir = args.sample

    if scan_dir:
        if not os.path.isdir(scan_dir):
            cprint(C.red + "  not a directory: %s" % scan_dir + C.reset)
            return 2
        if not args.no_banner:
            banner()
        return scan_directory(scan_dir, do_vt=args.vt, do_bazaar=args.bazaar,
                              do_yara=not args.no_yara)

    if not args.sample:
        banner()
        print_lab_tips()
        cprint(C.amber + "\n  usage: python3 necrobin.py [-i] <sample>\n" + C.reset)
        return 2

    if not os.path.isfile(args.sample):
        cprint(C.red + "  not a file: %s" % args.sample + C.reset)
        return 2

    if args.compare:
        other = args.other
        if not other or not os.path.isfile(other):
            cprint(C.red + "  --compare needs two existing files" + C.reset)
            return 2
        if not args.no_banner:
            banner()
        compare_files(args.sample, other)
        return 0

    if args.interactive:
        interactive(args.sample, do_vt=args.vt)
        return 0

    if not args.no_banner and not args.report and not args.json:
        banner()
        flag("info", "STATIC ONLY — bytes are read, never executed.")

    sample = Autopsy(args.sample)
    sample.load()
    sample.analyze(do_vt=args.vt, do_yara=not args.no_yara)
    if args.bazaar:
        sample.bazaar = bazaar_lookup(sample.hashes.get("sha256", ""))

    if args.extract_dir:
        written = sample.extract_artifacts(args.extract_dir)
        for w in written:
            flag("ok", "wrote " + w)
        if not written:
            flag("info", "nothing to extract")

    if args.iocs:
        payload = sample.ioc_text()
        out = args.output or (args.sample + ".iocs.txt")
        if out == "-":
            sys.stdout.write(payload)
        else:
            with open(out, "w", encoding="utf-8") as f:
                f.write(payload)
            flag("ok", "wrote " + out)
        if not args.report and not args.json and not args.html and not args.sarif and not args.stix and not args.misp:
            return 0

    export = None
    if args.html:
        export = (args.output or args.sample + ".necrobin.html", sample.to_html())
    elif args.sarif:
        export = (args.output or args.sample + ".necrobin.sarif.json", sample.to_sarif())
    elif args.stix:
        export = (args.output or args.sample + ".necrobin.stix.json", sample.to_stix2())
    elif args.misp:
        export = (args.output or args.sample + ".necrobin.misp.json", sample.to_misp())
    elif args.report or args.json:
        export = (
            args.output or (args.sample + (".necrobin.json" if args.json else ".necrobin.txt")),
            json.dumps(sample.to_json(), indent=2, default=str) if args.json else sample.to_text_report(),
        )
    if export:
        out, payload = export
        if out == "-":
            sys.stdout.write(payload if payload.endswith("\n") else payload + "\n")
        else:
            with open(out, "w", encoding="utf-8") as f:
                f.write(payload)
            if not args.no_banner:
                flag("ok", "wrote " + out)
        return 0

    sample.print_full(strings_n=args.strings)
    if args.hex:
        off, ln = parse_hex_arg(args.hex)
        sample.print_hex(off, ln)
    print()
    rule("─", 78, C.slate)
    cprint(C.ash + "  hint: python3 necrobin.py -i %s   ·   --tips" % args.sample + C.reset)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        cprint("\n" + C.ash + "  interrupted." + C.reset)
        sys.exit(130)
