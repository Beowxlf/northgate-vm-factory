# NorthGate no-secret bootstrap media toolkit

## Status and boundary

This folder renders and validates **proposed, unpromoted** unattended-install media for the fixed NorthGate fleet. It does not authorize or create a VM, attach media, change a switch/VLAN/firewall/DNS record, join a domain, enroll an agent, or promote an image/profile. Generated bundles and ISOs are ignored by Git.

The builder never edits an authorized source ISO. It verifies the exact filename, byte size, SHA-256, architecture, boot content, firmware binding, and (for Windows) Windows 11 Pro image index 6; extracts a read-only source into a bounded scratch directory; overlays a generated no-secret payload; creates a new derivative ISO; validates its UEFI boot entry and payload; rehashes the original source; and writes output provenance plus SHA-256 sidecars.

## Fixed source identities

| Image | Authorized filename | Bytes | SHA-256 | Gen2 firmware |
|---|---|---:|---|---|
| Debian 12.12 amd64 netinst | `debian-12.12.0-amd64-netinst.iso` | 704643072 | `dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531` | Secure Boot on, `MicrosoftUEFICertificateAuthority`, no vTPM |
| Windows 11 25H2 English x64 | `Win11_25H2_English_x64.iso` | 7736125440 | `d141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32` | Secure Boot on, `MicrosoftWindows`, vTPM required; Pro index 6; non-evaluation install, initially unactivated, no product key embedded |
| Kali 2026.2 installer netinst amd64 | `kali-linux-2026.2-installer-netinst-amd64.iso` | 779091968 | `d32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b` | Generation 2 UEFI, Secure Boot **off**, no vTPM; exception `NG-FW-20260802-KALI-UNSIGNED` |

The Debian public catalog ID is `debian-12.12-amd64-netinst`. A control-plane reference to `debian-12.12.0-amd64-netinst` is identity drift and must fail closed until separately reconciled. Kali's separate unsigned firmware profile is required because Kali's official installation guidance states that its kernel is not Secure-Boot signed. Windows and Debian retain their Secure Boot requirements.

Current host inventory on 2026-08-02 confirmed that all three filenames and byte sizes exist under the authorized Hyper-V ISO root. The BlueBench build recomputes the full SHA-256 every time; the repository record alone is never accepted as proof of the staged copy.

## Trust and secret model

- A request contains only a fixed asset/name/MAC/VLAN/address binding, non-secret network settings, a fixed role-hook ID, firmware facts, and a deterministic build epoch.
- The renderer accepts exactly one structurally valid `ssh-ed25519` public key from a file supplied at build time. It rejects options, multiple lines, RSA keys, malformed blobs, private-key markers, and credential-like request fields.
- No password, domain-join credential, TacticalRMM token, Wazuh enrollment secret, API key, product key, private key, recovery key, or application secret is accepted.
- Windows SetupComplete generates a unique local password directly into a `SecureString`; the value is never printed, written, serialized, or passed on a command line. Administration is key-only from `10.10.100.11`.
- Debian and Kali create a temporary sudo identity with a locked password, a single public key, OpenSSH public-key-only policy, and an nftables SSH restriction to `10.10.100.11`.
- Role hooks are fixed allowlisted offline code. The initial hooks record the reviewed role only; they deliberately do not download software or enroll agents.
- Domain join, TacticalRMM, Wazuh, LAPS, certificates, and application secrets occur later through their protected one-time workflows.

## Workflow

1. Reconcile the requested asset, name, static MAC, VLAN, IP, gateway, DNS, and hostname with live Hyper-V, OPNsense, DNS, the protected ledger, Wazuh, TacticalRMM, and the asset record. A quiet ping is not collision proof.
2. Select the fixed JSON request or create an exact equivalent that passes `Import-NorthGateBootstrapRequest`.
3. Supply the approved management **public** key by local file path. Never put the key path in the JSON request or commit a live key.
4. Render a deterministic bundle on the workstation using Windows PowerShell 5.1:

   ```powershell
   powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
     -File .\New-NorthGateBootstrapBundle.ps1 `
     -RequestPath .\examples\debian-canary.request.json `
     -AuthorizedPublicKeyPath C:\path\to\approved-bootstrap.pub `
     -OutputDirectory C:\approved-scratch\NG-DEB-CAN01-bundle
   ```

5. Transfer the bundle and a copy of the exact authorized source ISO to an owner-approved BlueBench scratch directory. Verify the transfer before building. Do not alter or replace the authoritative host copy.
6. On BlueBench, provide `python3`, `xorriso`, `genisoimage`, core utilities, and, for Windows, `7z` (`p7zip-full`) plus `wimlib-imagex` (`wimtools`). Windows source media is extracted from its validated UDF filesystem; Debian and Kali use their Rock Ridge filesystem. The build work root and output parent must already exist and must not be symlinks:

   ```sh
   ./bluebench/build-bootstrap-iso.sh \
     --source /approved-scratch/debian-12.12.0-amd64-netinst.iso \
     --bundle /approved-scratch/NG-DEB-CAN01-bundle \
     --output /approved-output/NG-DEB-CAN01-bootstrap.iso \
     --work-root /approved-work \
     --builder genisoimage
   ```

   `--builder xorriso` uses the same mkisofs-compatible option contract. The output is refused if it already exists.

7. Verify the output ISO SHA-256 and `.provenance.json`, then run the disposable Generation 2 canary tests in [acceptance.md](docs/acceptance.md). A static inspection proves an EFI boot catalog exists; only a disposable canary proves Hyper-V firmware compatibility and unattended completion.
8. Dismount the derivative ISO after the first successful boot. Enroll domain/RMM/Wazuh identities through separate bounded workflows, verify them, and then remove bootstrap access using [rollback-cleanup.md](docs/rollback-cleanup.md).

## Guest behavior

### Debian and Kali

The remaster inserts a one-second default UEFI/BIOS boot entry with `auto=true`, critical priority, a local `/cdrom/preseed.cfg`, and the Debian-installer-required MD5 for that local preseed. The SHA-256 trust boundary remains the bundle and final ISO manifests. Installation fails if more than one target disk is visible. The preseed configures the fixed address, gateway, DNS, hostname, one-disk partitioning, a locked temporary user, OpenSSH, sudo, nftables, and the fixed role marker.

Both inputs are netinst images. Before a canary boots, separately approve narrow DNS and HTTP/HTTPS egress to the selected distribution mirrors plus required time service. The toolkit does not create those OPNsense rules and does not weaken installation when the mirror is unavailable.

### Windows 11

`autounattend.xml` selects the non-evaluation Windows 11 Pro image at index 6 and wipes only disk 0 of a new one-disk canary. It embeds no product key and makes no activation claim; the initial expected licensing state is unactivated until a separately approved lab license is applied. The `$OEM$` payload places SetupComplete under `%WINDIR%\Setup\Scripts`; it validates the exact hostname and static MAC, disables DHCP, sets the fixed address/gateway/DNS suffix, creates the temporary local administrator with an in-memory-only credential, installs/enables OpenSSH Server, applies key-only/source-restricted SSH and firewall policy, and records non-secret status.

OpenSSH Server is a Windows capability. If its payload is unavailable or installation requires a reboot, SetupComplete records a failure and does not claim success. Canary network policy must provide an approved capability source or a separately hash-pinned offline Features-on-Demand source; no mutable package URL or token is embedded here. SetupComplete never reboots because Microsoft documents that rebooting from SetupComplete leaves Setup in a bad state.

## Determinism and provenance

Bundle JSON is normalized, templates are rendered with fixed line endings, every payload file is sorted and hashed, and the bundle-manifest hash is reproducible for identical request/key/template inputs. The ISO builder normalizes extracted file timestamps to `buildEpochUtc`, records the builder/version, hashes the derivative, and emits a canonical sorted JSON sidecar. Bit-for-bit ISO identity is accepted only for the same builder/version and inputs; the recorded output hash, not the requested filename, is the promoted artifact identity.

## Official implementation references

- [Debian Bookworm preseeding guide](https://www.debian.org/releases/bookworm/amd64/apbs02.en.html)
- [Kali PXE preseed example](https://www.kali.org/docs/installation/network-pxe/)
- [Kali installation and UEFI/Secure Boot guidance](https://www.kali.org/docs/installation/hard-disk-install/)
- [Microsoft Windows SetupComplete guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-a-custom-script-to-windows-setup?view=windows-11)
- [Microsoft image-index metadata guidance](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-setup-imageinstall-osimage-installfrom-metadata)
- [Microsoft Windows OpenSSH configuration](https://learn.microsoft.com/en-us/windows-server/administration/OpenSSH/openssh-server-configuration)
- [Microsoft Hyper-V Generation 2 Secure Boot templates](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/generation-2-virtual-machine-security-features)
