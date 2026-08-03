#!/usr/bin/env bash
set -euo pipefail
umask 022

fail() { printf '%s\n' "$1" >&2; exit 1; }
usage() {
  printf '%s\n' 'usage: build-bootstrap-iso.sh --source SOURCE.iso --bundle BUNDLE --output OUTPUT.iso --work-root DIR [--builder genisoimage|xorriso]'
}

source_iso=''
bundle=''
output=''
work_root=''
builder='genisoimage'
while (($#)); do
  case "$1" in
    --source) (($# >= 2)) || fail NGBM-BUILD-USAGE; source_iso=$2; shift 2 ;;
    --bundle) (($# >= 2)) || fail NGBM-BUILD-USAGE; bundle=$2; shift 2 ;;
    --output) (($# >= 2)) || fail NGBM-BUILD-USAGE; output=$2; shift 2 ;;
    --work-root) (($# >= 2)) || fail NGBM-BUILD-USAGE; work_root=$2; shift 2 ;;
    --builder) (($# >= 2)) || fail NGBM-BUILD-USAGE; builder=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail NGBM-BUILD-USAGE ;;
  esac
done

[[ -n "$source_iso" && -n "$bundle" && -n "$output" && -n "$work_root" ]] || fail NGBM-BUILD-USAGE
[[ "$builder" == genisoimage || "$builder" == xorriso ]] || fail NGBM-BUILDER-NOT-ALLOWED
for command in python3 sha256sum stat readlink xorriso find touch cp; do command -v "$command" >/dev/null || fail "NGBM-TOOL-MISSING-$command"; done
if [[ "$builder" == genisoimage ]]; then command -v genisoimage >/dev/null || fail NGBM-TOOL-MISSING-genisoimage; fi
command -v wimlib-imagex >/dev/null || true

[[ -f "$source_iso" && ! -L "$source_iso" ]] || fail NGBM-SOURCE-NOT-REGULAR
[[ -d "$bundle" && ! -L "$bundle" ]] || fail NGBM-BUNDLE-NOT-REGULAR
[[ -d "$work_root" && ! -L "$work_root" ]] || fail NGBM-WORK-ROOT-NOT-REGULAR
[[ ! -e "$output" && ! -L "$output" ]] || fail NGBM-OUTPUT-EXISTS

source_iso=$(readlink -f -- "$source_iso")
bundle=$(readlink -f -- "$bundle")
work_root=$(readlink -f -- "$work_root")
output_parent=$(readlink -f -- "$(dirname -- "$output")")
output="$output_parent/$(basename -- "$output")"
[[ "$source_iso" != "$output" ]] || fail NGBM-SOURCE-OUTPUT-COLLISION
case "$output/" in "$bundle/"*) fail NGBM-OUTPUT-IN-BUNDLE ;; esac

(cd "$bundle" && sha256sum --status -c bundle-manifest.sha256) || fail NGBM-BUNDLE-MANIFEST-HASH
mapfile -d '' values < <(python3 - "$bundle" <<'PY'
import hashlib, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1]).resolve()
manifest_path = root / "bundle-manifest.json"
try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit("NGBM-BUNDLE-MANIFEST-PARSE")
if manifest.get("schema") != "northgate/bootstrap-bundle/v1":
    raise SystemExit("NGBM-BUNDLE-MANIFEST-SCHEMA")
for record in manifest.get("files", []):
    rel = record.get("path", "")
    if not re.fullmatch(r"payload/[A-Za-z0-9$_.+/-]{1,240}", rel) or ".." in pathlib.PurePosixPath(rel).parts:
        raise SystemExit("NGBM-BUNDLE-PATH")
    target = root.joinpath(*pathlib.PurePosixPath(rel).parts)
    if not target.is_file() or target.is_symlink():
        raise SystemExit("NGBM-BUNDLE-FILE")
    data = target.read_bytes()
    if len(data) != record.get("sizeBytes") or hashlib.sha256(data).hexdigest() != record.get("sha256"):
        raise SystemExit("NGBM-BUNDLE-FILE-HASH")
source = manifest["source"]
firmware = manifest["firmware"]
items = [manifest["family"], manifest["assetId"], source["fileName"], source["sha256"], str(source["sizeBytes"]), source["architecture"], manifest["buildEpochUtc"], firmware["profile"], str(firmware["secureBoot"]).lower(), firmware["template"]]
for item in items:
    if "\x00" in item:
        raise SystemExit("NGBM-BUNDLE-VALUE")
    sys.stdout.write(item + "\x00")
PY
)
[[ ${#values[@]} -eq 10 ]] || fail NGBM-BUNDLE-VALUES
family=${values[0]}; asset_id=${values[1]}; expected_name=${values[2]}; expected_hash=${values[3]}; expected_size=${values[4]}; architecture=${values[5]}; build_epoch=${values[6]}; firmware_profile=${values[7]}; secure_boot=${values[8]}; secure_boot_template=${values[9]}
[[ "$family" =~ ^(debian|windows|kali)$ && "$asset_id" =~ ^NG-VM-[0-9]{3}$ && "$architecture" == x86_64 ]] || fail NGBM-BUNDLE-BINDING
[[ "$(basename -- "$source_iso")" == "$expected_name" ]] || fail NGBM-SOURCE-FILENAME-MISMATCH
[[ "$expected_hash" =~ ^[a-f0-9]{64}$ && "$expected_size" =~ ^[0-9]+$ ]] || fail NGBM-SOURCE-EXPECTATION

source_size_before=$(stat -c '%s' -- "$source_iso")
[[ "$source_size_before" == "$expected_size" ]] || fail NGBM-SOURCE-SIZE-MISMATCH
source_hash_before=$(sha256sum -- "$source_iso" | awk '{print $1}')
[[ "$source_hash_before" == "$expected_hash" ]] || fail NGBM-SOURCE-HASH-MISMATCH

stage=$(mktemp -d --tmpdir="$work_root" 'northgate-bootstrap.XXXXXXXX')
[[ "$stage/" == "$work_root/"* ]] || fail NGBM-STAGE-BOUNDARY
temporary_output="$stage/output.iso"
cleanup() { [[ -n "${stage:-}" && -d "$stage" && "$stage/" == "$work_root/"* ]] && rm -rf -- "$stage"; }
trap cleanup EXIT INT TERM
tree="$stage/tree"
mkdir -p -- "$tree"

if [[ "$family" == windows ]]; then
  command -v 7z >/dev/null || fail NGBM-TOOL-MISSING-7z
  archive_listing="$stage/source-archive.slt"
  7z l -slt "$source_iso" >"$archive_listing" || fail NGBM-WINDOWS-UDF-READ
  grep -Fqx 'Type = Udf' "$archive_listing" || fail NGBM-WINDOWS-UDF-REQUIRED
  7z x -y -bd -bso0 -bsp0 -o"$tree" "$source_iso" || fail NGBM-SOURCE-EXTRACT
else
  xorriso -osirrox on -indev "$source_iso" -extract / "$tree" >/dev/null 2>&1 || fail NGBM-SOURCE-EXTRACT
fi
chmod -R u+w -- "$tree"

python3 - "$bundle/bundle-manifest.json" "$tree" <<'PY'
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
tree = pathlib.Path(sys.argv[2]).resolve()
for raw in manifest["source"]["requiredIsoPaths"]:
    rel = pathlib.PurePosixPath(raw.lstrip("/"))
    target = tree.joinpath(*rel.parts)
    if not target.is_file() or target.is_symlink():
        raise SystemExit("NGBM-SOURCE-REQUIRED-PATH")
PY

if [[ "$family" == windows ]]; then
  command -v wimlib-imagex >/dev/null || fail NGBM-TOOL-MISSING-wimlib-imagex
  wim_info=$(wimlib-imagex info "$tree/sources/install.wim" 6) || fail NGBM-WINDOWS-WIM-READ
  grep -Fq 'Windows 11 Pro' <<<"$wim_info" || fail NGBM-WINDOWS-EDITION-MISMATCH
  grep -Eiq 'Architecture[[:space:]]*:[[:space:]]*(x86_64|amd64|9)' <<<"$wim_info" || fail NGBM-WINDOWS-ARCH-MISMATCH
  [[ "$firmware_profile" == windows-gen2 && "$secure_boot" == true && "$secure_boot_template" == MicrosoftWindows ]] || fail NGBM-WINDOWS-FIRMWARE-MISMATCH
elif [[ "$family" == debian ]]; then
  [[ -f "$tree/install.amd/vmlinuz" && "$firmware_profile" == linux-gen2 && "$secure_boot" == true && "$secure_boot_template" == MicrosoftUEFICertificateAuthority ]] || fail NGBM-DEBIAN-FIRMWARE-MISMATCH
else
  [[ -f "$tree/install.amd/vmlinuz" && "$firmware_profile" == kali-gen2-unsigned && "$secure_boot" == false && "$secure_boot_template" == Disabled ]] || fail NGBM-KALI-FIRMWARE-MISMATCH
fi

cp -a -- "$bundle/payload/." "$tree/"
if [[ "$family" != windows ]]; then
  python3 "$(dirname -- "$0")/remaster-linux-boot.py" "$tree" "$family"
fi

epoch_seconds=$(date -u -d "$build_epoch" '+%s') || fail NGBM-BUILD-EPOCH
find "$tree" -print0 | xargs -0 touch --no-dereference --date="@$epoch_seconds"
if [[ "$family" == windows ]]; then
  label='NGWINBOOT'
  mkisofs_args=(-iso-level 3 -udf -allow-limited-size -J -joliet-long -relaxed-filenames -D -N -b boot/etfsboot.com -no-emul-boot -boot-load-size 8 -eltorito-alt-boot -e efi/microsoft/boot/efisys.bin -no-emul-boot -V "$label" -o "$temporary_output" "$tree")
else
  [[ -f "$tree/isolinux/isolinux.bin" ]] || fail NGBM-LINUX-BIOS-BOOT-IMAGE
  label=$([[ "$family" == kali ]] && printf NGKALIBOOT || printf NGDEBBOOT)
  mkisofs_args=(-r -J -joliet-long -cache-inodes -V "$label" -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -o "$temporary_output" "$tree")
fi
if [[ "$builder" == genisoimage ]]; then genisoimage "${mkisofs_args[@]}" >/dev/null; else xorriso -as mkisofs "${mkisofs_args[@]}" >/dev/null 2>&1; fi

uefi_report=$(xorriso -indev "$temporary_output" -report_el_torito plain 2>&1) || fail NGBM-OUTPUT-EL-TORITO
grep -Eq 'UEFI|EFI' <<<"$uefi_report" || fail NGBM-OUTPUT-NO-UEFI-BOOT
if [[ "$family" == windows ]]; then
  xorriso -indev "$temporary_output" -ls /autounattend.xml >/dev/null 2>&1 || fail NGBM-OUTPUT-WINDOWS-PAYLOAD
  xorriso -indev "$temporary_output" -ls '/sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd' >/dev/null 2>&1 || fail NGBM-OUTPUT-WINDOWS-PAYLOAD
else
  xorriso -indev "$temporary_output" -ls /preseed.cfg >/dev/null 2>&1 || fail NGBM-OUTPUT-LINUX-PAYLOAD
  xorriso -indev "$temporary_output" -ls /northgate/authorized_key >/dev/null 2>&1 || fail NGBM-OUTPUT-LINUX-PAYLOAD
fi

source_size_after=$(stat -c '%s' -- "$source_iso")
source_hash_after=$(sha256sum -- "$source_iso" | awk '{print $1}')
[[ "$source_size_after" == "$source_size_before" && "$source_hash_after" == "$source_hash_before" ]] || fail NGBM-SOURCE-MUTATED

mv -- "$temporary_output" "$output"
chmod 0444 -- "$output"
output_hash=$(sha256sum -- "$output" | awk '{print $1}')
output_size=$(stat -c '%s' -- "$output")
manifest_hash=$(sha256sum -- "$bundle/bundle-manifest.json" | awk '{print $1}')
builder_version=$({ if [[ "$builder" == genisoimage ]]; then genisoimage --version; else xorriso -version; fi; } 2>&1 | head -n 1)
python3 - "$output.provenance.json" "$asset_id" "$family" "$source_hash_before" "$source_size_before" "$output_hash" "$output_size" "$manifest_hash" "$builder" "$builder_version" "$build_epoch" "$firmware_profile" "$secure_boot" "$secure_boot_template" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
record = {
    "assetId": sys.argv[2], "buildEpochUtc": sys.argv[11],
    "builder": {"name": sys.argv[9], "version": sys.argv[10]},
    "bundleManifestSha256": sys.argv[8], "family": sys.argv[3],
    "firmware": {"profile": sys.argv[12], "secureBoot": sys.argv[13] == "true", "template": sys.argv[14]},
    "output": {"fileName": path.name.removesuffix(".provenance.json"), "sha256": sys.argv[6], "sizeBytes": int(sys.argv[7])},
    "schema": "northgate/bootstrap-media-output-provenance/v1",
    "source": {"sha256": sys.argv[4], "sizeBytes": int(sys.argv[5])},
}
path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
PY
printf '%s  %s\n' "$output_hash" "$(basename -- "$output")" > "$output.sha256"
printf '%s\n' "NGBM_BUILD_OK asset=$asset_id output_sha256=$output_hash size=$output_size"
