# ComSniffer — Windows Serial Port Protocol Sniffer

A kernel-mode upper filter driver for Windows 10/11 that silently sits between
any program and a USB COM port, logging every byte read and written.

```
[LPG app]  ←→  [ComSniffer.sys — logs everything]  ←→  [usbser.sys]  ←→  [USB COM port]
```

No program modification needed. The app doesn't know we're there.

---

## Files

```
ComSniffer/
├── driver/
│   ├── comsniffer.c        ← Kernel filter driver (C, WDM)
│   ├── ComSniffer.vcxproj  ← Visual Studio / WDK project
│   └── ComSniffer.inf      ← Device installation file
├── viewer/
│   └── comsniffer_viewer.py ← Python hex viewer + protocol hints
└── scripts/
    ├── install.ps1          ← Installs + starts the driver
    └── uninstall.ps1        ← Removes everything
```

---

## Prerequisites

| Tool | Where to get it |
|---|---|
| Visual Studio 2019 or 2022 | https://visualstudio.microsoft.com/ |
| Windows Driver Kit (WDK) | https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk |
| Python 3.10+ | https://python.org |
| colorama (optional) | `pip install colorama` |

The WDK version must match your Windows SDK version.

---

## Step 1 — Enable Test Signing

You must do this **once** on your test machine. This lets Windows load drivers
that aren't Microsoft-signed. **Do this on a dev/test machine only.**

```powershell
# Run as Administrator
bcdedit /set testsigning on
Restart-Computer
```

You'll see a "Test Mode" watermark on your desktop — that's fine.

---

## Step 2 — Build the Driver

1. Open `driver/ComSniffer.vcxproj` in Visual Studio.
2. Make sure the WDK extension is installed (VS will prompt you if not).
3. Select **Debug | x64** (or Release).
4. Build → Build Solution.

Output: `driver/x64/Debug/ComSniffer.sys`

---

## Step 3 — Install

```powershell
# Run as Administrator in the ComSniffer folder
.\scripts\install.ps1
```

This will:
- Self-sign the driver with a generated test certificate
- Copy `ComSniffer.sys` to `System32\drivers`
- Register the service
- Install the INF (adds `UpperFilters` to the Ports device class)
- Restart your COM devices so the filter attaches

---

## Step 4 — Run the Viewer

Plug in your LPG kit and start the viewer **before** launching the LPG app:

```powershell
python viewer\comsniffer_viewer.py
```

Then start your LPG app normally. You'll see output like:

```
────────────────────────────────────────────────────────────
[14:32:01.847] WRITE ↓    5 bytes
  000000  AA 10 01 00 AB                            |.....|
  ↳ possible frame header: 0xAA | last byte matches XOR checksum (0xAB)

────────────────────────────────────────────────────────────
[14:32:01.853] READ  ↑   12 bytes
  000000  AA 10 81 00 1E 00 64 02 03 00 00 37       |......d....7|
  ↳ possible frame header: 0xAA
```

### Viewer options

```
--output FILE      Save log to FILE (default: timestamped filename)
--no-color         Plain text output
--min-bytes N      Skip short packets (noise filter)
```

---

## Targeting a Specific Device

The default INF attaches to **all** USB CDC serial ports. To attach only to
your LPG kit:

1. In Device Manager, right-click your COM port → Properties → Details.
2. Set "Property" to **Hardware IDs**. You'll see something like:
   `USB\VID_0403&PID_6001` (FTDI) or `USB\VID_10C4&PID_EA60` (CP210x).
3. In `ComSniffer.inf`, under `[Standard.NTamd64]`, replace:
   ```
   USB\Class_02&SubClass_02
   ```
   with your actual hardware ID:
   ```
   USB\VID_0403&PID_6001
   ```
4. Re-run `install.ps1`.

---

## How to Decode the Protocol

The viewer already detects:
- Frame headers (0xAA, 0x55 common in automotive ECU protocols)
- ASCII commands ending in CR / CRLF
- XOR checksums (last byte = XOR of all preceding bytes)

### Adding your own hints

Edit the `decode_lpg_hint()` function in `comsniffer_viewer.py`:

```python
def decode_lpg_hint(data, direction):
    hints = []

    # LPG kit uses: AA <cmd> <len> <data...> <xor_checksum>
    if len(data) >= 4 and data[0] == 0xAA:
        cmd = data[1]
        hints.append(f"LPG cmd=0x{cmd:02X}")
        if cmd == 0x01:
            hints.append("→ READ_SENSORS")
        elif cmd == 0x02:
            hints.append("→ SET_MAP")
        elif cmd == 0x10:
            hints.append("→ PING / HANDSHAKE")

    return " | ".join(hints) if hints else None
```

### Save and search logs

Logs are plain text. Use `grep` / `findstr` to find patterns:

```powershell
# Find all WRITE packets
Select-String "WRITE" comsniffer_20240622_143201.log

# Find packets with a specific byte sequence
Select-String "AA 10" comsniffer_20240622_143201.log
```

---

## Uninstall

```powershell
# Run as Administrator
.\scripts\uninstall.ps1

# Re-disable test signing (do this when you're done)
bcdedit /set testsigning off
Restart-Computer
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Cannot open \\.\ComSniffer` | Run `sc start ComSniffer` as admin |
| Driver won't load | Check test signing is ON (`bcdedit /enum {current}`) |
| No data appears | Unplug/replug the USB device; check Device Manager for the filter |
| Service starts but no IRPs | Confirm the INF hardware ID matches your device |
| BSOD on load | Build in Debug config; check WDK version matches SDK |

### Check if filter attached

```powershell
# Should show "ComSniffer" in UpperFilters
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E978-E325-11CE-BFC1-08002BE10318}" |
    Select-Object UpperFilters
```

### View kernel debug output (optional)

If built in Debug mode, the driver emits `DbgPrint` messages visible in:
- **DebugView** (Sysinternals) — enable "Capture Kernel" mode
- **WinDbg** with a kernel debug session

---

## Architecture Notes

The driver uses the standard WDM upper-filter pattern:

1. `DriverEntry` creates the `\\Device\\ComSniffer` control device and a 512 KB
   non-paged ring buffer.
2. `AddDevice` is called by PnP for each matching COM port. It calls
   `IoAttachDeviceToDeviceStack` to insert our filter object above the serial
   driver.
3. `IRP_MJ_WRITE` is intercepted **before** passing down: data is already in
   the buffer when `WriteFile` is called.
4. `IRP_MJ_READ` uses a **completion routine**: the lower driver fills the
   buffer, then our completion routine runs and copies the data to the log
   before marking the IRP complete to the app.
5. All other IRPs (`IOCTL`, `PnP`, `Power`) are passed through with
   `IoSkipCurrentIrpStackLocation`.
6. The viewer reads from `\\.\ComSniffer` using a regular `ReadFile` call.
   The kernel driver blocks (up to 500 ms) waiting for data, so the viewer
   loop is efficient — no busy-polling.

The filter is completely transparent: the app and hardware communicate exactly
as before, just with every byte logged.
