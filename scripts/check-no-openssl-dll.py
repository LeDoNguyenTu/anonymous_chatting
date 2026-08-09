#!/usr/bin/env python3
"""Fail when a shipped Windows binary imports a DLL the target may not have.

This check exists because v0.1.7 shipped and did not start. Every step of that
release passed — the build was green, all four artifacts existed, the checksums
matched — and all three .exe files imported `libcrypto-3-x64.dll`, a DLL the CI
runner happens to have and a clean Windows install does not. The first person to
run the installer got a loader error before the app drew a window.

Selecting rusqlite's `bundled-sqlcipher-vendored-openssl` feature is what fixes
that. This verifies the *artifact* rather than the configuration, because for a
whole release the two disagreed and only the artifact is what a user runs.

The PE import directory is parsed directly rather than shelled out to `dumpbin`
or `strings`. `dumpbin` needs a Visual Studio developer shell the release job
does not enter, and `strings` is not present on a stock Windows runner — it was
missing on the developer machine too, which is how this file came to exist. A
check that passes by failing to run is not a check (D-024).

Usage:
    python scripts/check-no-openssl-dll.py <exe> [<exe> ...]
"""

import struct
import sys

# Everything a binary is allowed to need. Deliberately a permitted-set rather
# than a list of known offenders: `libcrypto` was not on anyone's list either.
# `api-ms-win-*` are the Universal CRT forwarders, present since Windows 10.
ALLOWED_PREFIXES = ("api-ms-win-", "ext-ms-win-")
ALLOWED = {
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "combase.dll",
    # comctl32: the common-control library every Win32 UI links; present since
    # NT. Pulled in by the Tauri shell's native window chrome, not by us.
    "comctl32.dll",
    "crypt32.dll", "d3d12.dll", "dwmapi.dll", "dxgi.dll", "gdi32.dll",
    "iphlpapi.dll", "kernel32.dll", "msvcrt.dll", "ntdll.dll", "ole32.dll",
    "oleaut32.dll", "pdh.dll", "powrprof.dll", "propsys.dll",
    # psapi: process-status API, shipped with every Windows since NT 4. Reached
    # through a dependency's process introspection, not called directly here.
    "psapi.dll",
    "rpcrt4.dll",
    "secur32.dll", "shcore.dll", "shell32.dll", "shlwapi.dll", "user32.dll",
    "userenv.dll", "uxtheme.dll", "vcruntime140.dll", "vcruntime140_1.dll",
    "version.dll", "webview2loader.dll", "win32u.dll", "windows.ui.dll",
    "winhttp.dll", "wininet.dll", "winmm.dll", "ws2_32.dll",
}


def imported_dlls(path):
    """Return the DLL names in a PE file's import directory."""
    data = open(path, "rb").read()

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"{path}: not a PE image")

    n_sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    # The data-directory array sits after the optional header's fixed part,
    # which differs between PE32 (0x60) and PE32+ (0x70).
    dirs = opt + (0x60 if magic == 0x10B else 0x70)
    import_rva = struct.unpack_from("<I", data, dirs + 8)[0]
    if import_rva == 0:
        return []

    sections = []
    base = opt + opt_size
    for i in range(n_sections):
        off = base + i * 40
        va, size, raw = struct.unpack_from("<III", data, off + 12)
        sections.append((va, size, raw))

    def to_offset(rva):
        for va, size, raw in sections:
            if va <= rva < va + max(size, 1):
                return raw + (rva - va)
        raise ValueError(f"{path}: RVA {rva:#x} is outside every section")

    names, entry = [], to_offset(import_rva)
    while True:
        name_rva = struct.unpack_from("<I", data, entry + 12)[0]
        if name_rva == 0:
            break
        start = to_offset(name_rva)
        names.append(data[start:data.index(b"\0", start)].decode("ascii"))
        entry += 20
    return names


def main(paths):
    failed = False
    for path in paths:
        try:
            dlls = imported_dlls(path)
        except (OSError, ValueError) as exc:
            print(f"FAIL  {path}: {exc}")
            failed = True
            continue

        bad = sorted({
            d for d in dlls
            if d.lower() not in ALLOWED
            and not d.lower().startswith(ALLOWED_PREFIXES)
        })
        if bad:
            print(f"FAIL  {path}")
            for d in bad:
                print(f"          {d}")
            failed = True
        else:
            print(f"ok    {path}  {len(set(dlls))} imports, all system")

    if failed:
        print()
        print("A binary imports a DLL that a clean Windows install may not have,")
        print("so it would fail to start with a loader error before running any")
        print("code. If the name looks like OpenSSL, the workspace must select")
        print("rusqlite's bundled-sqlcipher-vendored-openssl feature and")
        print("OPENSSL_DIR must be unset for the build (D-054). If it is a")
        print("genuinely new system dependency, add it to ALLOWED above with a")
        print("note saying which Windows version ships it.")
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
