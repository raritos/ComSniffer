"""
comsniffer_viewer.py v2 — ComSniffer.sys user-space viewer

Displays:
  - READ  (device → app)  raw hex dump
  - WRITE (app → device)  raw hex dump
  - IOCTL line settings — decoded human-readable

Usage:
    python comsniffer_viewer.py [--output FILE] [--no-color] [--min-bytes N]
"""

import argparse, ctypes, ctypes.wintypes as wt
import struct, sys, time
from datetime import datetime

try:
    import colorama; colorama.init(); USE_COLOR = True
except ImportError:
    USE_COLOR = False

# ── ANSI ────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"; BOLD   = "\033[1m"
    RED    = "\033[91m"   # WRITE
    CYAN   = "\033[96m"   # READ
    GREEN  = "\033[92m"   # IOCTL SET
    YELLOW = "\033[93m"   # IOCTL GET / hints
    MAGENTA= "\033[95m"   # IOCTL signal (DTR/RTS/BREAK)
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"

def col(text, code):
    return f"{code}{text}{C.RESET}" if USE_COLOR else text

# ── Log entry header — must match kernel struct ──────────────────
# LARGE_INTEGER(8) + Type(1) + pad(3) + Code(4) + DataLength(4) = 20
ENTRY_HDR_FMT  = "<qBxxxII"
ENTRY_HDR_SIZE = struct.calcsize(ENTRY_HDR_FMT)   # 20 bytes

ENTRY_READ  = 0x01
ENTRY_WRITE = 0x02
ENTRY_IOCTL = 0x03

# ── Serial IOCTL codes (from ntddser.h / winsdk) ────────────────
# METHOD_BUFFERED = 0, FILE_ANY_ACCESS = 0, FILE_DEVICE_SERIAL_PORT = 0x1b
def _CTL(fn): return 0x001b0000 | (fn << 2)   # METHOD_BUFFERED, ANY_ACCESS

IOCTL_NAMES = {
    _CTL(1):  "SET_BAUD_RATE",
    _CTL(19): "GET_BAUD_RATE",
    _CTL(2):  "SET_QUEUE_SIZE",
    _CTL(3):  "SET_LINE_CONTROL",
    _CTL(20): "GET_LINE_CONTROL",
    _CTL(4):  "SET_BREAK_ON",
    _CTL(5):  "SET_BREAK_OFF",
    _CTL(6):  "IMMEDIATE_CHAR",
    _CTL(7):  "SET_TIMEOUTS",
    _CTL(21): "GET_TIMEOUTS",
    _CTL(8):  "GET_COMMSTATUS",
    _CTL(9):  "PURGE",
    _CTL(10): "GET_HANDFLOW",
    _CTL(11): "SET_HANDFLOW",
    _CTL(12): "GET_MODEMSTATUS",
    _CTL(13): "GET_DTRRTS",
    _CTL(14): "GET_COMMCONFIG",
    _CTL(15): "SET_COMMCONFIG",
    _CTL(16): "GET_CHARS",
    _CTL(17): "SET_CHARS",
    _CTL(18): "SET_DTR",
    _CTL(22): "CLR_DTR",
    _CTL(23): "RESET_DEVICE",
    _CTL(24): "SET_RTS",
    _CTL(25): "CLR_RTS",
    _CTL(26): "SET_XOFF",
    _CTL(27): "SET_XON",
    _CTL(28): "GET_WAIT_MASK",
    _CTL(29): "SET_WAIT_MASK",
    _CTL(30): "WAIT_ON_MASK",
    _CTL(31): "LSRMST_INSERT",
    _CTL(32): "CONFIG_SIZE",
    _CTL(33): "GET_STATS",
    _CTL(34): "CLEAR_STATS",
    _CTL(35): "GET_PROPERTIES",
    _CTL(36): "XOFF_COUNTER",
}

# ── Parity / stop-bit / word-len maps ────────────────────────────
PARITY = {0:"None", 1:"Odd", 2:"Even", 3:"Mark", 4:"Space"}
STOP   = {0:"1", 1:"1.5", 2:"2"}

# ── IOCTL data decoders ──────────────────────────────────────────
def decode_ioctl(code, data: bytes) -> list[str]:
    name = IOCTL_NAMES.get(code, f"0x{code:08X}")
    lines = [f"  IOCTL  {name}"]

    try:
        # SERIAL_BAUD_RATE { ULONG BaudRate; }
        if name in ("SET_BAUD_RATE", "GET_BAUD_RATE") and len(data) >= 4:
            baud, = struct.unpack_from("<I", data)
            lines.append(f"    Baud rate    : {baud:,} bps")

        # SERIAL_LINE_CONTROL { UCHAR StopBits; UCHAR Parity; UCHAR WordLength; }
        elif name in ("SET_LINE_CONTROL", "GET_LINE_CONTROL") and len(data) >= 3:
            stop, parity, bits = struct.unpack_from("<BBB", data)
            lines.append(f"    Word length  : {bits} bits")
            lines.append(f"    Parity       : {PARITY.get(parity, parity)}")
            lines.append(f"    Stop bits    : {STOP.get(stop, stop)}")

        # SERIAL_TIMEOUTS (5 x ULONG)
        elif name in ("SET_TIMEOUTS", "GET_TIMEOUTS") and len(data) >= 20:
            ri, rm, rc, wm, wc = struct.unpack_from("<IIIII", data)
            lines.append(f"    ReadIntervalTimeout         : {ri} ms")
            lines.append(f"    ReadTotalTimeoutMultiplier  : {rm} ms")
            lines.append(f"    ReadTotalTimeoutConstant    : {rc} ms")
            lines.append(f"    WriteTotalTimeoutMultiplier : {wm} ms")
            lines.append(f"    WriteTotalTimeoutConstant   : {wc} ms")
            if ri == 0xFFFFFFFF and rm == 0 and rc == 0:
                lines.append(f"    → Non-overlapped immediate return (no wait)")
            elif ri == 0 and rm == 0 and rc == 0:
                lines.append(f"    → No read timeout (wait forever)")

        # SERIAL_HANDFLOW { ULONG ControlHandShake; ULONG FlowReplace;
        #                   LONG  XonLimit;          LONG  XoffLimit; }
        elif name in ("SET_HANDFLOW", "GET_HANDFLOW") and len(data) >= 16:
            ctrl, flow, xon, xoff = struct.unpack_from("<IIiI", data)
            hs_bits = []
            if ctrl & 0x01: hs_bits.append("DTR_CONTROL")
            if ctrl & 0x02: hs_bits.append("DTR_HANDSHAKE")
            if ctrl & 0x04: hs_bits.append("CTS_HANDSHAKE")
            if ctrl & 0x08: hs_bits.append("DSR_HANDSHAKE")
            if ctrl & 0x10: hs_bits.append("DCD_HANDSHAKE")
            if ctrl & 0x20: hs_bits.append("DSR_SENSITIVITY")
            if ctrl & 0x40: hs_bits.append("ERROR_ABORT")
            fl_bits = []
            if flow & 0x01: fl_bits.append("AUTO_TRANSMIT (XON/XOFF TX)")
            if flow & 0x02: fl_bits.append("AUTO_RECEIVE  (XON/XOFF RX)")
            if flow & 0x04: fl_bits.append("ERROR_CHAR")
            if flow & 0x08: fl_bits.append("NULL_STRIPPING")
            if flow & 0x10: fl_bits.append("BREAK_CHAR")
            if flow & 0x40: fl_bits.append("RTS_CONTROL")
            if flow & 0x80: fl_bits.append("RTS_HANDSHAKE")
            lines.append(f"    ControlHandShake : {', '.join(hs_bits) or 'None'}")
            lines.append(f"    FlowReplace      : {', '.join(fl_bits) or 'None'}")
            lines.append(f"    XON  limit       : {xon} bytes")
            lines.append(f"    XOFF limit       : {xoff} bytes")

        # SERIAL_PURGE { ULONG PurgeFlags; }
        elif name == "PURGE" and len(data) >= 4:
            flags, = struct.unpack_from("<I", data)
            what = []
            if flags & 0x01: what.append("PURGE_TXABORT")
            if flags & 0x02: what.append("PURGE_RXABORT")
            if flags & 0x04: what.append("PURGE_TXCLEAR")
            if flags & 0x08: what.append("PURGE_RXCLEAR")
            lines.append(f"    Flags : {' | '.join(what) or hex(flags)}")

        # SERIAL_QUEUE_SIZE { ULONG InSize; ULONG OutSize; }
        elif name == "SET_QUEUE_SIZE" and len(data) >= 8:
            ins, outs = struct.unpack_from("<II", data)
            lines.append(f"    RX buffer : {ins} bytes")
            lines.append(f"    TX buffer : {outs} bytes")

        # SERIAL_CHARS { EofChar XoffChar XonChar ErrorChar BreakChar EventChar }
        elif name in ("SET_CHARS", "GET_CHARS") and len(data) >= 6:
            eof, xoff, xon, err, brk, evt = struct.unpack_from("<BBBBBB", data)
            lines.append(f"    EOF char   : 0x{eof:02X}")
            lines.append(f"    XON char   : 0x{xon:02X}  XOFF char: 0x{xoff:02X}")
            lines.append(f"    Error char : 0x{err:02X}  Break chr: 0x{brk:02X}")
            lines.append(f"    Event char : 0x{evt:02X}")

        # SERIAL_WAIT_MASK { ULONG Mask; }
        elif name in ("SET_WAIT_MASK", "GET_WAIT_MASK") and len(data) >= 4:
            mask, = struct.unpack_from("<I", data)
            bits = []
            if mask & 0x0001: bits.append("EV_RXCHAR")
            if mask & 0x0002: bits.append("EV_RXFLAG")
            if mask & 0x0004: bits.append("EV_TXEMPTY")
            if mask & 0x0008: bits.append("EV_CTS")
            if mask & 0x0010: bits.append("EV_DSR")
            if mask & 0x0020: bits.append("EV_RLSD")
            if mask & 0x0040: bits.append("EV_BREAK")
            if mask & 0x0080: bits.append("EV_ERR")
            if mask & 0x0100: bits.append("EV_RING")
            if mask & 0x0200: bits.append("EV_PERR")
            if mask & 0x0400: bits.append("EV_RX80FULL")
            if mask & 0x2000: bits.append("EV_EVENT1")
            if mask & 0x4000: bits.append("EV_EVENT2")
            lines.append(f"    Wait mask : {' | '.join(bits) or 'None (0)'}")

        # GET_MODEMSTATUS { ULONG ModemStatus; }
        elif name == "GET_MODEMSTATUS" and len(data) >= 4:
            ms, = struct.unpack_from("<I", data)
            sigs = []
            if ms & 0x10: sigs.append("CTS")
            if ms & 0x20: sigs.append("DSR")
            if ms & 0x40: sigs.append("RING")
            if ms & 0x80: sigs.append("DCD/RLSD")
            lines.append(f"    Active signals : {', '.join(sigs) or 'None'}")

        # Signal-only IOCTLs (no data, action is the name)
        elif name in ("SET_DTR","CLR_DTR","SET_RTS","CLR_RTS",
                      "SET_BREAK_ON","SET_BREAK_OFF","RESET_DEVICE"):
            state = "ON" if name.startswith("SET") else "OFF"
            sig   = name.replace("SET_","").replace("CLR_","")
            lines.append(f"    Signal : {sig} → {state}")

        elif len(data) > 0:
            # Fall-through: show raw hex
            lines.append(f"    Raw ({len(data)} bytes): "
                         + " ".join(f"{b:02X}" for b in data[:32])
                         + ("…" if len(data) > 32 else ""))

    except struct.error:
        lines.append(f"    (parse error — {len(data)} bytes)")

    return lines

# ── Hex dump ─────────────────────────────────────────────────────
def hex_dump(data: bytes, color="") -> list[str]:
    BPL = 16
    out = []
    for i in range(0, len(data), BPL):
        ch   = data[i:i+BPL]
        addr = f"{i:06X}"
        hex_ = " ".join(f"{b:02X}" for b in ch)
        pad  = "   " * (BPL - len(ch))
        asc  = "".join(chr(b) if 32<=b<127 else "." for b in ch)
        line = f"  {addr}  {hex_}{pad}  |{asc}|"
        out.append(col(line, color) if color else line)
    return out

# ── Timestamp ────────────────────────────────────────────────────
FT_EPOCH = 116444736000000000

def ts_str(ticks):
    if ticks <= 0: return "??:??:??.???"
    dt = datetime.fromtimestamp((ticks - FT_EPOCH) / 1e7)
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond//1000:03d}"

# ── LPG protocol hints ───────────────────────────────────────────
def lpg_hint(data: bytes) -> str | None:
    if not data: return None
    hints = []
    if data[0] in (0xAA, 0x55):
        hints.append(f"frame header 0x{data[0]:02X}")
    if all(32 <= b < 127 or b in (9,10,13) for b in data):
        hints.append(f"ASCII: {data.decode('ascii','replace')!r}")
    elif len(data) >= 2 and data[-2:] == b'\r\n':
        hints.append(f"CRLF frame: {data[:-2].decode('ascii','replace')!r}")
    if len(data) > 2:
        xor = 0
        for b in data[:-1]: xor ^= b
        if xor == data[-1]:
            hints.append(f"XOR checksum OK (0x{xor:02X})")
    return " | ".join(hints) if hints else None

# ── Win32 device I/O ─────────────────────────────────────────────
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
INVALID = ctypes.c_void_p(-1).value

def open_device():
    h = ctypes.windll.kernel32.CreateFileW(
        r"\\.\ComSniffer", GENERIC_READ, 0, None,
        OPEN_EXISTING, 0, None)
    if h == INVALID:
        err = ctypes.windll.kernel32.GetLastError()
        raise OSError(
            f"Cannot open \\\\.\\ComSniffer (error {err})\n"
            "  Is ComSniffer.sys running?  sc start ComSniffer")
    return h

def dev_read(h, size=65536) -> bytes:
    buf = ctypes.create_string_buffer(size)
    n   = wt.DWORD(0)
    ok  = ctypes.windll.kernel32.ReadFile(h, buf, size, ctypes.byref(n), None)
    if not ok:
        raise OSError(f"ReadFile error {ctypes.windll.kernel32.GetLastError()}")
    return buf.raw[:n.value]

# ── Parse ring-buffer stream ─────────────────────────────────────
def parse(raw: bytes):
    pos = 0
    while pos + ENTRY_HDR_SIZE <= len(raw):
        ts, typ, code, dlen = struct.unpack_from(ENTRY_HDR_FMT, raw, pos)
        pos += ENTRY_HDR_SIZE
        if pos + dlen > len(raw):
            return raw[pos - ENTRY_HDR_SIZE:]   # incomplete; save for next round
        data = raw[pos:pos+dlen]
        pos += dlen
        yield ts, typ, code, data
    return b""

# ── Main ─────────────────────────────────────────────────────────
def run(args):
    global USE_COLOR
    if args.no_color: USE_COLOR = False

    log_path = args.output or \
        f"comsniffer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    print(col("ComSniffer v2  —  full serial port logger", C.BOLD + C.WHITE))
    print(col("  CYAN    = READ  (device → app)", C.CYAN))
    print(col("  RED     = WRITE (app → device)", C.RED))
    print(col("  GREEN   = IOCTL SET (app configures port)", C.GREEN))
    print(col("  YELLOW  = IOCTL GET (app reads port state)", C.YELLOW))
    print(col("  MAGENTA = IOCTL signal (DTR/RTS/BREAK)", C.MAGENTA))
    print(f"  Logging to: {log_path}")
    print("  Ctrl-C to stop\n")

    h = open_device()
    leftover = b""
    tot_r = tot_w = tot_i = 0
    SEP = "─" * 62

    with open(log_path, "w", encoding="utf-8") as lf:
        def emit(*parts):
            line = " ".join(str(p) for p in parts)
            # strip ANSI for file
            import re
            clean = re.sub(r"\033\[[0-9;]*m", "", line)
            print(line)
            lf.write(clean + "\n")
            lf.flush()

        try:
            while True:
                raw = dev_read(h)
                if not raw:
                    time.sleep(0.05)
                    continue

                raw = leftover + raw
                leftover = b""
                gen = parse(raw)

                for ts, typ, code, data in gen:

                    if typ == ENTRY_READ:
                        if args.min_bytes and len(data) < args.min_bytes:
                            continue
                        tot_r += len(data)
                        emit(col(SEP, C.CYAN))
                        emit(col(f"[{ts_str(ts)}] READ  ↑  {len(data):4d} bytes  (device → app)", C.CYAN + C.BOLD))
                        for l in hex_dump(data, C.CYAN): emit(l)
                        h_ = lpg_hint(data)
                        if h_: emit(col(f"  ↳ {h_}", C.YELLOW))

                    elif typ == ENTRY_WRITE:
                        if args.min_bytes and len(data) < args.min_bytes:
                            continue
                        tot_w += len(data)
                        emit(col(SEP, C.RED))
                        emit(col(f"[{ts_str(ts)}] WRITE ↓  {len(data):4d} bytes  (app → device)", C.RED + C.BOLD))
                        for l in hex_dump(data, C.RED): emit(l)
                        h_ = lpg_hint(data)
                        if h_: emit(col(f"  ↳ {h_}", C.YELLOW))

                    elif typ == ENTRY_IOCTL:
                        tot_i += 1
                        name = IOCTL_NAMES.get(code, f"0x{code:08X}")
                        is_sig = name in ("SET_DTR","CLR_DTR","SET_RTS","CLR_RTS",
                                          "SET_BREAK_ON","SET_BREAK_OFF","RESET_DEVICE")
                        is_get = name.startswith("GET_")
                        clr = C.MAGENTA if is_sig else (C.YELLOW if is_get else C.GREEN)
                        dir_ = "GET ←" if is_get else "SET →"
                        emit(col(SEP, clr))
                        emit(col(f"[{ts_str(ts)}] IOCTL {dir_}  {name}", clr + C.BOLD))
                        for l in decode_ioctl(code, data):
                            emit(col(l, clr))

        except KeyboardInterrupt:
            pass
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
            emit(f"\n{SEP}")
            emit(f"Session ended.")
            emit(f"  Data IN      : {tot_r:,} bytes")
            emit(f"  Data OUT     : {tot_w:,} bytes")
            emit(f"  IOCTL events : {tot_i}")
            emit(f"  Log file     : {log_path}")

def main():
    p = argparse.ArgumentParser(description="ComSniffer v2 viewer")
    p.add_argument("--output",    help="Log file path")
    p.add_argument("--no-color",  action="store_true")
    p.add_argument("--min-bytes", type=int, default=0, metavar="N")
    args = p.parse_args()
    if sys.platform != "win32":
        print("Windows only."); sys.exit(1)
    run(args)

if __name__ == "__main__":
    main()
