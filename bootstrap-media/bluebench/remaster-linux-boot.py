#!/usr/bin/env python3
"""Insert a deterministic, local-preseed boot entry without downloading content."""

from __future__ import annotations

import hashlib
import pathlib
import sys


def fail(code: str) -> None:
    raise SystemExit(code)


if len(sys.argv) != 3:
    fail("NGBM-REMOUNT-USAGE")

tree = pathlib.Path(sys.argv[1]).resolve()
family = sys.argv[2]
if family not in {"debian", "kali"} or not tree.is_dir():
    fail("NGBM-REMOUNT-INPUT")

preseed = tree / "preseed.cfg"
kernel = tree / "install.amd" / "vmlinuz"
initrd = tree / "install.amd" / "initrd.gz"
grub = tree / "boot" / "grub" / "grub.cfg"
for required in (preseed, kernel, initrd, grub):
    if not required.is_file() or required.is_symlink():
        fail("NGBM-REMOUNT-REQUIRED-FILE")

checksum = hashlib.md5(preseed.read_bytes()).hexdigest()  # Debian installer requires MD5 for preseed/file/checksum.
marker = "# NORTHGATE_BOOTSTRAP_ENTRY_V1"
args = (
    "auto=true priority=critical interface=auto "
    f"preseed/file=/cdrom/preseed.cfg preseed/file/checksum={checksum} --- quiet"
)
entry = (
    f"{marker}\n"
    "set default=0\n"
    "set timeout=1\n"
    "menuentry 'NorthGate unattended install' {\n"
    f"    linux /install.amd/vmlinuz {args}\n"
    "    initrd /install.amd/initrd.gz\n"
    "}\n\n"
)
current = grub.read_text(encoding="utf-8", errors="strict")
if marker in current:
    fail("NGBM-REMOUNT-ENTRY-ALREADY-PRESENT")
grub.write_text(entry + current.replace("\r\n", "\n"), encoding="utf-8", newline="\n")

isolinux = tree / "isolinux" / "txt.cfg"
if isolinux.is_file() and not isolinux.is_symlink():
    bios = (
        f"{marker}\n"
        "default ngauto\n"
        "timeout 10\n"
        "label ngauto\n"
        "  menu label ^NorthGate unattended install\n"
        "  kernel /install.amd/vmlinuz\n"
        f"  append initrd=/install.amd/initrd.gz {args}\n\n"
    )
    existing = isolinux.read_text(encoding="utf-8", errors="strict")
    if marker in existing:
        fail("NGBM-REMOUNT-ENTRY-ALREADY-PRESENT")
    isolinux.write_text(bios + existing.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
