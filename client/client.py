#!/usr/bin/env python3
"""
Recursively iterate an FTP/FTPS server, write directory+file links,
generate link files (aria2/wget/curl/PowerShell), and optionally clone
the remote subtree locally using aria2.

Highlights:
- Regex controls:
    -r/--regex                 : include (both files & dirs, basename)
    -rf/--regex-file           : include files only
    -rd/--regex-dir            : include directories only
    -xrd/--exclude-regex-dir   : exclude directories only
  (Excludes win. Dir regex gates file eligibility in that dir. We still traverse all dirs.)

- Full ftp/ftps URL as first arg is supported (ftp://user:pass@host:port/path).
  CLI flags override URL values.

- --link-file {aria2,wget,curl,powershell}   (multiple allowed)
- --keep-structure                           (per-file relative dir)

- --embed-user-pass                          (embed user:pass@host:port in generated links)
  NOTE: --clone behaves as if --embed-user-pass is ON by default.

- --clone [--clone-dir NAME]                 (clone subtree using aria2c; requires aria2c)
"""

from __future__ import annotations
import argparse
import contextlib
import ftplib
import posixpath
import sys
import socket
import re
import os
import shutil
import tempfile
import subprocess
from urllib.parse import urlparse, unquote, quote

# ------------------------
# URL / path helpers
# ------------------------
def print_examples():
    print("""
========================
📦 FTP Walk: Examples
========================

🔍 Basic Recursive Listing
--------------------------
  python ftp_walk.py ftp://user:pass@host:port/
  
  python ftp_walk.py ftp://user:pass@host:port/Download/Videos

📄 Only Include Specific Extensions
-----------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ -e pdf -e txt

🧹 Ignore Specific Extensions
-----------------------------
  python ftp_walk.py ftp://user:pass@host:port/ -ie tmp -ie bak

📁 Exclude Entire Directory (prune scan)
----------------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ -xrd "(?i)Android"

📁 Include Only Certain Directories (filter only)
-------------------------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ -rd "(?i)Miglani"

📂 Include Files Only If Name Matches
-------------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ -rf "(?i)^report.*\\.pdf$"

📌 Match Files/Dirs by Full Path
--------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ -r "MIUI/debug_log"

🎯 Combine: Only PDFs inside MIUI directory
------------------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ -e pdf -r "^/MIUI/"

📥 Generate Aria2 Link File
---------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --link-file aria2 --keep-structure --embed-user-pass

🌐 Generate cURL Link File
--------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --link-file curl

🔗 Embed FTP Credentials in Links (Default for clone)
------------------------------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --embed-user-pass

📁 Clone FTP Server Using Aria2
-------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --clone

📁 Clone to Specific Directory
-------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --clone --clone-dir my_ftp_backup

🎛 Combine Clone with Filters
-----------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --clone -e pdf -xrd "Android" -rf "report"
  
📁 Download All Files Using Aria2
-------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --download (or -d)

📁 Clone to Specific Directory
-------------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --download (or -d) --download-dir my_ftp_backup (or -ddir)

🎛 Combine Clone with Filters
-----------------------------
  python ftp_walk.py ftp://user:pass@host:port/ --download -e pdf -xrd "Android" -rf "report"

🗂 Verbose Mode
---------------
  python ftp_walk.py ftp://user:pass@host:port/ -v

ℹ️  Notes:
 - Use `(?i)` in regex for case-insensitive matching.
 - Port is required if IP address is used.
 - `--keep-structure` is needed to preserve original FTP folder layout in downloads.
 - `--embed-user-pass` adds username:password to generated links (useful for aria2).

    """)

def _bracket_host_if_ipv6(host: str) -> str:
    # urlparse() .hostname is without brackets; add them for IPv6 literals
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host

def make_url(host: str,
             path: str,
             secure: bool,
             user: str | None = None,
             password: str | None = None,
             port: int | None = None,
             embed: bool = False,
             always_include_port: bool = False) -> str:
    """
    Build an ftp/ftps URL.
    - embed=True includes "user:pass@" in the authority (URL-encoded).
    - If always_include_port=True, append ":port" (uses default 21 if None).
    """
    scheme = "ftps" if secure else "ftp"
    if not path.startswith("/"):
        path = "/" + path

    # Encode path segments (keep '/')
    parts = [quote(p, safe="") for p in path.split("/")]
    enc_path = "/".join(parts)

    authority = ""
    if embed and user is not None:
        u = quote(user, safe="")
        p = quote(password or "", safe="")
        authority += f"{u}:{p}@"

    # Host (add brackets for IPv6)
    host_part = _bracket_host_if_ipv6(host)

    # Port
    if always_include_port:
        port = port or 21
        authority += f"{host_part}:{port}"
    else:
        if port and port != 21:
            authority += f"{host_part}:{port}"
        else:
            authority += host_part

    return f"{scheme}://{authority}{enc_path}"

def safe_join(parent: str, child: str) -> str:
    if parent in ("", "/"):
        return "/" + child.strip("/")
    return posixpath.join(parent, child)

def rel_from_start(path: str, start_root: str) -> str:
    p_norm = path.rstrip("/") or "/"
    s_norm = start_root.rstrip("/") or "/"
    if p_norm == s_norm:
        return "."
    rel = posixpath.relpath(p_norm, s_norm)
    return "./" + rel.strip("/")

# ------------------------
# FTP capability / probing
# ------------------------

def try_enable_mlsd(ftp: ftplib.FTP) -> bool:
    try:
        with contextlib.suppress(Exception):
            ftp.sendcmd("OPTS MLST type;size;modify;perm;")
        next(ftp.mlsd(".", facts=[]))
        return True
    except Exception:
        return False

def is_dir_by_cwd(ftp: ftplib.FTP, path: str) -> bool:
    cur = ftp.pwd()
    try:
        ftp.cwd(path)
        ftp.cwd(cur)
        return True
    except Exception:
        with contextlib.suppress(Exception):
            ftp.cwd(cur)
        return False

# ------------------------
# Full URL parsing (positional arg)
# ------------------------

def parse_ftp_url(maybe_url: str):
    if not (maybe_url.startswith("ftp://") or maybe_url.startswith("ftps://")):
        return None
    u = urlparse(maybe_url)
    if u.scheme not in ("ftp", "ftps"):
        return None
    host = u.hostname or ""
    port = u.port or 21
    user = unquote(u.username) if u.username else None
    password = unquote(u.password) if u.password else None
    start_path = u.path or "/"
    secure = (u.scheme == "ftps")
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "start_path": start_path,
        "secure": secure,
    }

# ------------------------
# Per-directory listing
# ------------------------

def list_dir_mlsd(ftp: ftplib.FTP, base: str):
    files, dirs = [], []
    for name, facts in ftp.mlsd(base):
        if name in (".", ".."):
            continue
        full = safe_join(base, name)
        etype = (facts.get("type") or "").lower()
        if etype in ("dir", "cdir", "pdir"):
            dirs.append(full)
        elif etype == "file":
            files.append(full)
        else:
            if is_dir_by_cwd(ftp, full):
                dirs.append(full)
            else:
                files.append(full)
    return files, dirs

def list_dir_portable(ftp: ftplib.FTP, base: str):
    files, dirs = [], []
    try:
        items = ftp.nlst(base)
    except Exception as e:
        print(f"Warning: NLST failed at {base}: {e}", file=sys.stderr)
        return files, dirs
    for item in items:
        name = item if item.startswith("/") else safe_join(base, item)
        last = posixpath.basename(name.rstrip("/"))
        if last in (".", ".."):
            continue
        if is_dir_by_cwd(ftp, name):
            dirs.append(name)
        else:
            files.append(name)
    return files, dirs

# ------------------------
# Filters & regexes
# ------------------------

def _normalize_exts(values: list[str] | None) -> tuple[str, ...]:
    if not values:
        return ()
    out: list[str] = []
    for v in values:
        if not v:
            continue
        parts = [p.strip() for p in v.split(",") if p.strip()]
        for p in parts:
            if not p.startswith("."):
                p = "." + p
            out.append(p.lower())
    return tuple(out)

def compile_regexes(patterns: list[str] | None) -> list[re.Pattern]:
    if not patterns:
        return []
    return [re.compile(p) for p in patterns]

def basename(path: str) -> str:
    return posixpath.basename(path.rstrip("/"))

def passes_regex(name: str,
                 include_any: list[re.Pattern],
                 exclude_any: list[re.Pattern]) -> bool:
    if include_any and not any(r.search(name) for r in include_any):
        return False
    if exclude_any and any(r.search(name) for r in exclude_any):
        return False
    return True

def file_passes_filters(file_abs_path: str,
                        include_exts: tuple[str, ...],
                        ignore_exts: tuple[str, ...],
                        regex_both_inc: list[re.Pattern],
                        regex_both_exc: list[re.Pattern],
                        regex_file_inc: list[re.Pattern],
                        regex_file_exc: list[re.Pattern],
                        base_dir_ok: bool) -> bool:
    if not base_dir_ok:
        return False
    name = basename(file_abs_path)
    name_lower = name.lower()
    if not passes_regex(name, regex_both_inc, regex_both_exc):
        return False
    if not passes_regex(name, regex_file_inc, regex_file_exc):
        return False
    if include_exts and not name_lower.endswith(include_exts):
        return False
    if ignore_exts and name_lower.endswith(ignore_exts):
        return False
    return True

def dir_passes_regex(dir_abs_path: str,
                     regex_both_inc: list[re.Pattern],
                     regex_both_exc: list[re.Pattern],
                     regex_dir_inc: list[re.Pattern],
                     regex_dir_exc: list[re.Pattern]) -> bool:
    dname = basename(dir_abs_path) or "/"
    if not passes_regex(dname, regex_both_inc, regex_both_exc):
        return False
    if not passes_regex(dname, regex_dir_inc, regex_dir_exc):
        return False
    return True

# ------------------------
# Collect eligible files per directory
# ------------------------

def traverse_and_collect(ftp: ftplib.FTP,
                         start_root: str,
                         prefer_mlsd: bool,
                         include_exts: tuple[str, ...],
                         ignore_exts: tuple[str, ...],
                         regex_both_inc: list[re.Pattern],
                         regex_both_exc: list[re.Pattern],   # ignored by simplified rules
                         regex_file_inc: list[re.Pattern],
                         regex_file_exc: list[re.Pattern],    # ignored by simplified rules
                         regex_dir_inc: list[re.Pattern],
                         regex_dir_exc: list[re.Pattern]):
    """
    Walk the tree depth-first from start_root and collect (dir_abs, [file_abs...]) for
    directories that have INCLUDED files, with simplified regex semantics:

      - xrd  (regex_dir_exc):   *PRUNE NOW* — if a directory BASENAME matches, we SKIP it
                                COMPLETELY (no listing, no descent). This omits scanning.

      - rd   (regex_dir_inc):   *NO SCANNING OMIT* — we still traverse all dirs, but at the end
                                we only KEEP results for directories whose BASENAME matches.

      - rf   (regex_file_inc):  *FILES ONLY* — we only KEEP files whose BASENAME matches.
                                (Does not affect traversal.)

      - r    (regex_both_inc):  *FULL-PATH FILTER* — we only KEEP entries (dirs/files) whose
                                FULL PATH matches this pattern (regex search; use ^$ for full match).
                                (Does not affect traversal.)

      - regex_both_exc / regex_file_exc are intentionally ignored under the simplified rules.

    Extension filters still apply to files:
      - include_exts: path must end with one of these (case-insensitive tuple prepared upstream)
      - ignore_exts: path must NOT end with one of these

    Returns:
      results: list of (dir_abs, [file_abs...]) where each dir has at least one kept file
      use_mlsd: whether MLSD was used
    """
    use_mlsd = prefer_mlsd and try_enable_mlsd(ftp)
    lister = list_dir_mlsd if use_mlsd else list_dir_portable

    stack = [start_root]
    visited: set[str] = set()
    results: list[tuple[str, list[str]]] = []

    # Helpers
    def _bname(p: str) -> str:
        return posixpath.basename(p.rstrip("/")) or "/"

    def _matches_any(s: str, pats: list[re.Pattern]) -> bool:
        return any(r.search(s) for r in pats)

    while stack:
        base = stack.pop()
        if base in visited:
            continue
        visited.add(base)

        base_name = _bname(base)

        # --- PRUNE NOW: xrd (exclude directory) omits scanning entirely ---
        # Allow start_root to be considered for pruning too; if you prefer to always scan root,
        # wrap this in `if base != start_root:`.
        if regex_dir_exc and _matches_any(base_name, regex_dir_exc):
            continue

        # List current directory
        try:
            files, dirs = lister(ftp, base)
        except Exception as e:
            print(f"Warning: listing failed at {base}: {e}", file=sys.stderr)
            files, dirs = [], []

        kept_files: list[str] = []

        # --- FILE FILTERS (rf, r, include_exts, ignore_exts); no effect on traversal ---
        for f in files:
            fname = _bname(f)
            fname_lower = fname.lower()

            # include_exts gate
            if include_exts and not fname_lower.endswith(include_exts):
                continue

            # ignore_exts gate
            if ignore_exts and fname_lower.endswith(ignore_exts):
                continue

            # rf: include only if file BASENAME matches any rf pattern (when provided)
            if regex_file_inc and not _matches_any(fname, regex_file_inc):
                continue

            # r: full-path filter — keep only if full path matches (when provided)
            if regex_both_inc and not _matches_any(f, regex_both_inc):
                continue

            kept_files.append(f)

        # --- DIRECTORY FILTERS at the end (rd + r) determine if this dir result is kept ---
        # Start optimistic; drop if any required filter fails.
        dir_keep = True

        # rd: keep dir only if its BASENAME matches at least one provided pattern
        if regex_dir_inc and not _matches_any(base_name, regex_dir_inc):
            dir_keep = False

        # r: full-path filter on the directory path itself
        if dir_keep and regex_both_inc and not _matches_any(base, regex_both_inc):
            dir_keep = False

        # Only record this directory if it passes dir filters AND has at least one kept file
        if dir_keep and kept_files:
            results.append((base, sorted(kept_files)))

        # --- Traverse children: only prune by xrd; rd/r do NOT omit scanning ---
        for d in sorted(dirs, reverse=True):
            d_name = _bname(d)

            # xrd pruning on children
            if regex_dir_exc and _matches_any(d_name, regex_dir_exc):
                continue

            stack.append(d)

    return results, use_mlsd

# ------------------------
# Writers
# ------------------------

def write_normal_listing(out_path: str, host: str, secure: bool, start_root: str, dir_files: list[tuple[str, list[str]]]):
    count_dirs = 0
    count_files = 0
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for dir_abs, files in dir_files:
            rel_dir = rel_from_start(dir_abs, start_root)
            f.write(f"[DIR]  {rel_dir}\n")
            count_dirs += 1
            for file_abs in files:
                # KEEP listing URLs without credentials (as before)
                url = make_url(host, file_abs, secure, embed=False, always_include_port=False)
                f.write(f"[FILE] {url}\n")
                count_files += 1
    return count_dirs, count_files

def ensure_outstem(path: str) -> tuple[str, str]:
    base = os.path.basename(path)
    stem, ext = os.path.splitext(base)
    return stem, ext

def out_path_for(base_out: str, kind: str) -> str:
    stem, _ = ensure_outstem(base_out)
    if kind == "aria2":
        return f"{stem}.aria2.txt"
    if kind == "wget":
        return f"{stem}.wget.sh"
    if kind == "curl":
        return f"{stem}.curl.sh"
    if kind == "powershell":
        return f"{stem}.powershell.ps1"
    return f"{stem}.{kind}.txt"

def to_windows_rel(rel_dir: str) -> str:
    if rel_dir == ".":
        return "."
    if rel_dir.startswith("./"):
        rel_dir = rel_dir[2:]
    return ".\\" + rel_dir.replace("/", "\\")

def write_link_files(kinds: list[str],
                     base_out: str,
                     keep_structure: bool,
                     host: str,
                     secure: bool,
                     user: str | None,
                     password: str | None,
                     port: int | None,
                     start_root: str,
                     dir_files: list[tuple[str, list[str]]],
                     embed_user_pass: bool):
    results = {}
    for kind in kinds:
        path = out_path_for(base_out, kind)
        written = 0

        if kind == "aria2":
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                for dir_abs, files in dir_files:
                    rel_dir = rel_from_start(dir_abs, start_root)
                    for file_abs in files:
                        # Always include :port when embedding (requirement), else include when non-default
                        url = make_url(host, file_abs, secure,
                                       user=user, password=password, port=port,
                                       embed=embed_user_pass, always_include_port=embed_user_pass or (port and port != 21))
                        f.write(f"{url}\n")
                        if keep_structure:
                            f.write(f"  dir={rel_dir}\n")
                        f.write("\n")
                        written += 1

        elif kind == "wget":
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write("#!/usr/bin/env bash\nset -euo pipefail\n\n")
                for dir_abs, files in dir_files:
                    rel_dir = rel_from_start(dir_abs, start_root)
                    for file_abs in files:
                        url = make_url(host, file_abs, secure,
                                       user=user, password=password, port=port,
                                       embed=embed_user_pass, always_include_port=embed_user_pass or (port and port != 21))
                        name = basename(file_abs)
                        if keep_structure:
                            f.write(f"mkdir -p '{rel_dir}' && wget -c -O '{rel_dir}/{name}' '{url}'\n")
                        else:
                            f.write(f"wget -c '{url}'\n")
                        written += 1
            if os.name != "nt":
                with contextlib.suppress(Exception):
                    os.chmod(path, 0o755)

        elif kind == "curl":
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write("#!/usr/bin/env bash\nset -euo pipefail\n\n")
                for dir_abs, files in dir_files:
                    rel_dir = rel_from_start(dir_abs, start_root)
                    for file_abs in files:
                        url = make_url(host, file_abs, secure,
                                       user=user, password=password, port=port,
                                       embed=embed_user_pass, always_include_port=embed_user_pass or (port and port != 21))
                        name = basename(file_abs)
                        if keep_structure:
                            f.write(f"mkdir -p '{rel_dir}' && curl -L -C - -o '{rel_dir}/{name}' '{url}'\n")
                        else:
                            f.write(f"curl -L -C - -O '{url}'\n")
                        written += 1
            if os.name != "nt":
                with contextlib.suppress(Exception):
                    os.chmod(path, 0o755)

        elif kind == "powershell":
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write("$ErrorActionPreference = 'Stop'\n\n")
                for dir_abs, files in dir_files:
                    rel_dir = rel_from_start(dir_abs, start_root)
                    rel_win = to_windows_rel(rel_dir)
                    for file_abs in files:
                        url = make_url(host, file_abs, secure,
                                       user=user, password=password, port=port,
                                       embed=embed_user_pass, always_include_port=embed_user_pass or (port and port != 21))
                        name = basename(file_abs)
                        if keep_structure:
                            f.write(f"$d = '{rel_win}'; if (-not (Test-Path $d)) {{ New-Item -ItemType Directory -Force -Path $d | Out-Null }}\n")
                            f.write(f"Invoke-WebRequest -Uri '{url}' -OutFile (Join-Path $d '{name}')\n")
                        else:
                            f.write(f"Invoke-WebRequest -Uri '{url}' -OutFile '.\\{name}'\n")
                        written += 1

        else:
            print(f"Warning: unknown --link-file kind '{kind}', skipping.", file=sys.stderr)
            continue

        results[kind] = (path, written)

    return results

# ------------------------
# Getting path to supplied aria2c
# ------------------------

def get_aria2c_path() -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    aria2c_path = os.path.join(base_dir, r"aria2", r"aria2c.exe")
    if os.name != 'nt':
        print("[WARN]: Cannot find any installations of aria2!")
        print("[WARN]: Please install aria2 for your operating system!")
        sys.exit(3)
        return "aria2c"
    if os.path.isfile(aria2c_path):
        return aria2c_path
    else:
        print("WARN: 'aria2c' not found in PATH.", file=sys.stderr)
        raise FileNotFoundError(f"ERR: Cannot find 'aria2c.exe' supplied with project, please install aria2")

# ------------------------
# Clone via aria2
# ------------------------

def run_clone_with_aria2(dir_files: list[tuple[str, list[str]]],
                         host: str,
                         secure: bool,
                         user: str | None,
                         password: str | None,
                         port: int | None,
                         start_root: str,
                         dest_dir: str):
    aria2c = r"aria2c"
    if shutil.which("aria2c") is None:
        print("Trying aria2c from supplied with project ...")
        aria2c = get_aria2c_path()
        # sys.exit(3)

    os.makedirs(dest_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        aria2_path = os.path.join(td, "clone.aria2.txt")
        with open(aria2_path, "w", encoding="utf-8", newline="\n") as f:
            for dir_abs, files in dir_files:
                rel_dir = rel_from_start(dir_abs, start_root)
                for file_abs in files:
                    # In clone, embed creds and ALWAYS include port (default if missing)
                    url = make_url(host, file_abs, secure,
                                   user=user, password=password, port=port,
                                   embed=True, always_include_port=True)
                    f.write(f"{url}\n")
                    f.write(f"  dir={rel_dir}\n\n")

        cmd = [aria2c, "-i", aria2_path, "-j", "8", "-s", "16", "-x", "16", "--continue=true", "--auto-file-renaming=false"]
        print(f"[clone] Running: {' '.join(cmd)}  (cwd={dest_dir})")
        proc = subprocess.run(cmd, cwd=dest_dir)
        if proc.returncode != 0:
            print(f"ERROR: aria2c exited with code {proc.returncode}.", file=sys.stderr)
            sys.exit(proc.returncode)

# ------------------------
# Download via aria2
# ------------------------

def run_download_with_aria2(dir_files: list[tuple[str, list[str]]],
                            host: str,
                            secure: bool,
                            user: str | None,
                            password: str | None,
                            port: int | None,
                            start_root: str,
                            dest_dir: str):
    aria2c = r"aria2c"
    if shutil.which("aria2c") is None:
        print("Trying aria2c supplied with project ...")
        aria2c = get_aria2c_path()
        # sys.exit(3)
        
    os.makedirs(dest_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        aria2_path = os.path.join(td, "download.aria2.txt")
        with open(aria2_path, "w", encoding="utf-8", newline="\n") as f:
            for dir_abs, files in dir_files:
                for file_abs in files:
                    filename = os.path.basename(file_abs)
                    url = make_url(host, file_abs, secure,
                                   user=user, password=password, port=port,
                                   embed=True, always_include_port=True)
                    f.write(f"{url}\n")
                    f.write(f"  out={filename}\n\n")  # Force flat structure

        cmd = [aria2c, "-i", aria2_path, "-j", "8", "-s", "16", "-x", "16", "--continue=true", "--auto-file-renaming=false"]
        print(f"[download] Running: {' '.join(cmd)}  (cwd={dest_dir})")
        proc = subprocess.run(cmd, cwd=dest_dir)
        if proc.returncode != 0:
            print(f"ERROR: aria2c exited with code {proc.returncode}.", file=sys.stderr)
            sys.exit(proc.returncode)

# ------------------------
# Main
# ------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Recursively list an FTP/FTPS server, generate link files (aria2/wget/curl/PowerShell), or clone using aria2."
    )
    ap.add_argument("host_or_url", help="FTP host (e.g., 192.168.1.51) OR full ftp/ftps URL (e.g., ftp://user:pass@host:2121/path)")
    ap.add_argument("-u", "--user", help="Username (overrides URL credentials)")
    ap.add_argument("-p", "--password", help="Password (overrides URL credentials)")
    ap.add_argument("--port", type=int, help="Port (overrides URL port; default 21)")
    ap.add_argument("--ftps", action="store_true", help="Use explicit TLS (overrides URL scheme)")
    ap.add_argument("--start", help="Start path on server (overrides URL path; default '/')")
    ap.add_argument("--out", default="ftp_links.txt", help="Base output name (used for listing and link files)")
    ap.add_argument("--active", action="store_true", help="Use active mode (default: passive)")
    ap.add_argument("--timeout", type=float, default=30.0, help="Socket timeout in seconds (default: 30)")
    ap.add_argument("--no-mlsd", action="store_true", help="Disable MLSD preference and use portable listing")

    # Extensions
    ap.add_argument("-e", "--extension", action="append",
                    help="Include only these file extensions (case-insensitive). Repeat or comma-separate.")
    ap.add_argument("-ie", "--ignore-extension", action="append",
                    help="Exclude these file extensions (case-insensitive). Repeat or comma-separate.")

    # Regex include/exclude
    ap.add_argument("-r", "--regex", action="append", help="Filter regex (applies to BOTH files & dirs; basename).")
    ap.add_argument("-rf", "--regex-file", action="append", help="Filter regex for FILES only (basename).")
    ap.add_argument("-rd", "--regex-dir", action="append", help="Filter regex for DIRECTORIES only (basename).")
    ap.add_argument("-xrd", "--exclude-regex-dir", action="append", help="Exclude regex for DIRECTORIES only.")
    
    ap.add_argument("-xr", "--exclude-regex", action="append", help=argparse.SUPPRESS) #  help="[Deprecated Ignored] Exclude regex (applies to BOTH files & dirs)."
    ap.add_argument("-xrf", "--exclude-regex-file", action="append", help=argparse.SUPPRESS) # help="[Deprecated Ignored] Exclude regex for FILES only."

    # Link files
    ap.add_argument("--link-file", action="append", choices=["aria2", "wget", "curl", "powershell"],
                    help="Generate a link file for the given tool. Can be specified multiple times.")
    ap.add_argument("--keep-structure", action="store_true",
                    help="Keep relative directory structure in generated link files (per-file dir).")
    ap.add_argument("--embed-user-pass", action="store_true",
                    help="Embed user:pass@host:port in generated links. (Clone mode implies this by default.)")

    # Clone
    ap.add_argument("--clone", action="store_true", help="Clone the server subtree into a local folder using aria2c.")
    ap.add_argument("--clone-dir", help="Destination directory name for --clone (default: host name).")

    # Download
    ap.add_argument("-d","--download", action="store_true", help="Download the server files into a local folder using aria2c. Ignored if --clone is used")
    ap.add_argument("-ddir","--download-dir", help="Destination directory name for --download (default: host name).")
    
    # Examples
    ap.add_argument("--examples", action="store_true",help="Show usage examples for all features and exit.")

    # Printing Examples
    if sys.argv[1:].__contains__('--example'):
        print_examples()
        sys.exit(0)
    
    args = ap.parse_args() # parsed later so to pre-evaluate example
    
    
    # Deprecation Notice
    if args.exclude_regex:
        print("[WARN] -xr is deprecated and will be ignored under the simplified rules.")

    if args.exclude_regex_file:
        print("[WARN] -xrf is deprecated and will be ignored under the simplified rules.")

    # URL or host?
    url_info = parse_ftp_url(args.host_or_url)
    if url_info:
        host = url_info["host"]
        port = url_info["port"]
        url_user = url_info["user"]
        url_pass = url_info["password"]
        url_start = url_info["start_path"]
        url_secure = url_info["secure"]
    else:
        host = args.host_or_url
        port = 21
        url_user = None
        url_pass = None
        url_start = "/"
        url_secure = False

    # Effective connection params (CLI overrides URL)
    user = args.user or url_user or "anonymous"
    password = args.password or url_pass or "anonymous"
    port = args.port or port or 21
    secure = args.ftps or url_secure
    start_path = args.start if args.start else url_start
    if not start_path.startswith("/"):
        start_path = "/" + start_path

    prefer_mlsd = not args.no_mlsd

    # Filters
    include_exts = _normalize_exts(args.extension)
    ignore_exts = _normalize_exts(args.ignore_extension)
    try:
        regex_both_inc = compile_regexes(args.regex)
        regex_both_exc = compile_regexes(args.exclude_regex)
        regex_file_inc = compile_regexes(args.regex_file)
        regex_file_exc = compile_regexes(args.exclude_regex_file)
        regex_dir_inc  = compile_regexes(args.regex_dir)
        regex_dir_exc  = compile_regexes(args.exclude_regex_dir)
    except re.error as e:
        print(f"Invalid regex: {e}", file=sys.stderr)
        sys.exit(2)

    # Decide embedding behavior for link files:
    # - If --clone is used, treat embed as ON by default (even if --embed-user-pass is not given).
    # - Otherwise, embed only if --embed-user-pass was provided.
    embed_for_links = bool(args.embed_user_pass or args.clone)

    ftp_cls = ftplib.FTP_TLS if secure else ftplib.FTP

    try:
        with ftp_cls() as ftp:
            ftp.encoding = "utf-8"
            ftp.timeout = args.timeout
            ftp.connect(host=host, port=port, timeout=args.timeout)

            if secure and isinstance(ftp, ftplib.FTP_TLS):
                ftp.auth()
                ftp.prot_p()

            ftp.login(user=user, passwd=password)
            ftp.set_pasv(not args.active)

            ftp.cwd(start_path)
            start_abs = ftp.pwd()

            # Collect eligible files per directory
            dir_files, used_mlsd = traverse_and_collect(
                ftp=ftp,
                start_root=start_abs,
                prefer_mlsd=prefer_mlsd,
                include_exts=include_exts,
                ignore_exts=ignore_exts,
                regex_both_inc=regex_both_inc,
                regex_both_exc=regex_both_exc,
                regex_file_inc=regex_file_inc,
                regex_file_exc=regex_file_exc,
                regex_dir_inc=regex_dir_inc,
                regex_dir_exc=regex_dir_exc,
            )

            # Normal listing (no credentials in listing file)
            listing_path = args.out
            n_dirs, n_files = write_normal_listing(
                out_path=listing_path,
                host=host,
                secure=secure,
                start_root=start_abs,
                dir_files=dir_files,
            )
            print(f"Listing: wrote {n_dirs} directories and {n_files} files to '{listing_path}' "
                  f"using {'MLSD' if used_mlsd else 'portable'} mode.")

            # Link files (optional)
            created = {}
            if args.link_file:
                created = write_link_files(
                    kinds=args.link_file,
                    base_out=args.out,
                    keep_structure=args.keep_structure,
                    host=host,
                    secure=secure,
                    user=user,
                    password=password,
                    port=port,
                    start_root=start_abs,
                    dir_files=dir_files,
                    embed_user_pass=embed_for_links,
                )
                for kind, (path, count) in created.items():
                    print(f"Link file ({kind}): wrote {count} entries to '{path}'.")

                # Sample commands
                print("\nSample commands:")
                for kind, (path, _) in created.items():
                    if kind == "aria2":
                        print(f"  aria2c -i '{path}' -j 8 -s 16 -x 16 --continue=true")
                    elif kind == "wget":
                        print(f"  bash '{path}'")
                    elif kind == "curl":
                        print(f"  bash '{path}'")
                    elif kind == "powershell":
                        print(f"  powershell -ExecutionPolicy Bypass -File '{path}'")

            # Clone (optional)
            if args.clone:
                dest = args.clone_dir or host
                run_clone_with_aria2(
                    dir_files=dir_files,
                    host=host,
                    secure=secure,
                    user=user,
                    password=password,
                    port=port,
                    start_root=start_abs,
                    dest_dir=dest
                )
                print(f"[clone] Completed into '{dest}'.")
            elif args.download:
                dest = args.download_dir or host
                run_download_with_aria2(
                    dir_files=dir_files,
                    host=host,
                    secure=secure,
                    user=user,
                    password=password,
                    port=port,
                    start_root=start_abs,
                    dest_dir=dest
                )

    except (ftplib.all_errors, socket.error) as e:
        print(f"FTP error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()