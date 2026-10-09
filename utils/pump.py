#!/usr/bin/env python3
"""
pump.py - talk to a Hayward OmniX pump directly over BLE from macOS.

This implements the exact application protocol used by the Hayward OmniX
("OmniFlex") app, recovered from its Hermes JS bundle:

  * GATT service 0000fca5-0000-1000-8000-00805f9b34fb
  * one vendor "pipe" characteristic (appMessageUUID,
    66460130-8759-9bf8-b4db-7b04b9b026f1)
  * authentication: read the pump's 16-byte challenge, reply with
    AES-128-ECB(challenge, securityKey).  session id = first 8 bytes.
  * every command: plaintext = header(0x02) + mac(6) + UBJSON(CmdObj)
    and is sent as  AES-128-GCM(key=securityKey,
                                iv = frameCounter(4 BE) || sessionId(8))
    wire = 0x07 || ciphertext || frameCounter(4) || authTag(16)
  * the pump answers with  ciphertext || frameCounter(4) || authTag(16)
    using the same frame counter (it is echoed).

THE ONE THING YOU MUST HAVE
----------------------------
`securityKey`: a per-device 16-byte AES key.  It is NOT in a BLE sniff and
cannot be derived from it.  It is written to the pump when you set it up in the
Hayward app, and the pump rejects every command without it.  This tool does not
provide it and does not talk to any Hayward service; supply your own key.

Install:
    python3 -m pip install bleak cryptography
"""

import argparse
import asyncio
import json
import random
import struct
import time
from dataclasses import dataclass

# --------------------------------------------------------------------------
# pklg (Apple PacketLogger) parsing + ATT extraction
# --------------------------------------------------------------------------

def load_pklg(path):
    """Yield (offset, secs, usecs, packet_bytes) for every packetlogger record."""
    data = open(path, "rb").read()
    off = 0
    while off + 4 <= len(data):
        ln = struct.unpack_from("<I", data, off)[0]
        payload = data[off + 4: off + 4 + ln]
        if len(payload) < ln:
            break
        secs, usecs = struct.unpack_from("<II", payload, 0)
        yield off, secs, usecs, payload[8:]
        off += 4 + ln


def u16(b, o=0):
    return struct.unpack_from("<H", b, o)[0]


@dataclass
class Att:
    ts: float
    sent: bool            # True = host -> controller (app -> pump)
    conn_handle: int      # ACL connection handle
    att_handle: int       # attribute handle (for writes / reads)
    opcode: int
    value: bytes          # ATT value (without opcode)
    channel: int


def iter_att(path):
    """Yield every ATT PDU carried in ACL packets."""
    for _off, secs, usecs, p in load_pklg(path):
        if not p or p[0] not in (0x02, 0x03):
            continue
        handle = u16(p, 1) & 0x0FFF
        dlen = u16(p, 3)
        d = p[5:5 + dlen]
        if len(d) < 4:
            continue
        l2len = u16(d, 0)
        cid = u16(d, 2)
        att = d[4:4 + l2len]
        if not att:
            continue
        op = att[0]
        value = b""
        valhandle = handle
        if op in (0x12, 0x52) and len(att) >= 3:
            valhandle = u16(att, 1)
            value = att[3:]
        elif op == 0x0A and len(att) >= 3:    # read request
            valhandle = u16(att, 1)
        else:                                  # read rsp / notify / indicate
            value = att[1:]
        yield Att(secs + usecs / 1e6, p[0] == 0x02, handle, valhandle, op,
                  value, cid)


# --------------------------------------------------------------------------
# crypto
# --------------------------------------------------------------------------

def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return c.update(data) + c.finalize()


def _aes_gcm_encrypt(key: bytes, iv: bytes, pt: bytes,
                     aad: bytes = b"") -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).encrypt(iv, pt, aad)


def _aes_gcm_decrypt(key: bytes, iv: bytes, ct: bytes,
                     aad: bytes = b"") -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(iv, ct, aad)


def parse_key(s: str) -> bytes:
    """Accept 32 hex chars, a UUID, or '0x..'. Must be 16 bytes."""
    s = s.strip()
    if s.startswith("0x"):
        s = s[2:]
    s = s.replace("-", "")
    key = bytes.fromhex(s)
    if len(key) != 16:
        raise SystemExit(f"security key must be 16 bytes, got {len(key)}")
    return key


# Wire framing: the 4-byte frame counter and 16-byte GCM tag are appended to
# the ciphertext, so every frame carries FRAME_OVERHEAD extra bytes.
FRAME_OVERHEAD = 20


def split_frame(data):
    """Return (frame_counter, ciphertext, auth_tag) from a wire frame."""
    fc = struct.unpack_from(">I", data, len(data) - FRAME_OVERHEAD)[0]
    return fc, data[:-FRAME_OVERHEAD], data[-16:]


def make_request(key, session_id, fc, plaintext):
    """Frame a command: 0x07 || ciphertext || fc || authTag."""
    iv = struct.pack(">I", fc) + session_id
    wire = _aes_gcm_encrypt(key, iv, plaintext)
    return b"\x07" + wire[:-16] + struct.pack(">I", fc) + wire[-16:]


def open_reply(key, session_id, data):
    """Decrypt a reply frame.  Returns (frame_counter, plaintext|None).

    The pump encrypts its replies with iv = fc || reversed(session.id); the
    non-reversed form is tried as a fallback.
    """
    fc, ct, tag = split_frame(data)
    for sid in (session_id[::-1], session_id):
        try:
            iv = struct.pack(">I", fc) + sid
            return fc, _aes_gcm_decrypt(key, iv, ct + tag)
        except Exception:
            pass
    return fc, None


# --------------------------------------------------------------------------
# minimal UBJSON encode/decode (enough for the OmniX CmdObj)
# --------------------------------------------------------------------------

def ubjson_decode(buf: bytes):
    """Decode UBJSON bytes into python objects (best-effort, never hangs).

    Raises ValueError on truncated/invalid input; callers wrap it in try.
    """
    i = 0
    n = len(buf)

    def need(k):
        if i + k > n:
            raise ValueError("truncated UBJSON")

    def rd_int() -> int:
        v = rd()
        if not isinstance(v, int):
            raise ValueError("length is not an int")
        return v

    def rd_val(t: str):
        nonlocal i
        if t == "Z":
            return None
        if t == "T":
            return True
        if t == "F":
            return False
        if t in ("i", "U", "I"):
            # i = int8, U = uint8, I = int16 (per @shelacek/ubjson)
            sz = {"i": 1, "U": 1, "I": 2}[t]
            need(sz)
            v = int.from_bytes(buf[i:i + sz], "big", signed=t in ("i", "I"))
            i += sz
            return v
        if t in ("l", "L"):
            sz = 4 if t == "l" else 8
            need(sz)
            v = int.from_bytes(buf[i:i + sz], "big", signed=(t == "l"))
            i += sz
            return v
        if t == "d":
            need(4)
            v = struct.unpack_from(">f", buf, i)[0]
            i += 4
            return v
        if t == "D":
            need(8)
            v = struct.unpack_from(">d", buf, i)[0]
            i += 8
            return v
        if t in ("s", "S", "C", "H"):
            ln = rd_int()
            need(ln)
            s = buf[i:i + ln]
            i += ln
            return s.decode("latin1", "replace")
        raise ValueError(f"unknown UBJSON type {t!r}")

    def rd():
        nonlocal i
        need(1)
        t = chr(buf[i])
        i += 1
        if t == "{":
            # @shelacek/ubjson writes object keys as a length-prefixed string
            # WITHOUT a leading type marker (the S type is implied).
            obj = {}
            while True:
                need(1)
                if buf[i] == ord("}"):
                    i += 1
                    return obj
                klen = rd_int()
                need(klen)
                k = buf[i:i + klen].decode("latin1", "replace")
                i += klen
                obj[k] = rd()
        if t == "[":
            arr = []
            if i < n and buf[i] == ord("$"):   # typed array
                i += 1
                need(1)
                typ = chr(buf[i])
                i += 1
                if i < n and buf[i] == ord("#"):
                    i += 1
                    cnt = rd_int()
                else:
                    cnt = rd_int()
                for _ in range(cnt):
                    arr.append(rd_val(typ))
                return arr
            if i < n and buf[i] == ord("#"):
                i += 1
                cnt = rd_int()
                for _ in range(cnt):
                    arr.append(rd())
                return arr
            while True:
                need(1)
                if buf[i] == ord("]"):
                    i += 1
                    return arr
                arr.append(rd())
        return rd_val(t)

    return rd()


def _ubjson_type(v):
    """Minimal UBJSON type marker for a value, per @shelacek/ubjson."""
    if v is None:
        return "Z"
    if isinstance(v, bool):
        return "T" if v else "F"
    if isinstance(v, str):
        return "C" if len(v) == 1 and ord(v) <= 127 else "S"
    if isinstance(v, int):
        if -128 <= v <= 127:
            return "i"
        if 0 <= v <= 255:
            return "U"
        if -32768 <= v <= 32767:
            return "I"
        return "l"
    if isinstance(v, float):
        return "d" if struct.unpack(">f", struct.pack(">f", v))[0] == v else "D"
    if isinstance(v, dict):
        return "{"
    if isinstance(v, (list, tuple, bytes, bytearray)):
        return "["
    raise TypeError(type(v))


def _ubjson_scalar(v):
    """Type marker + payload for a scalar (no string/length handling)."""
    t = _ubjson_type(v)
    if t == "Z":
        return b"Z"
    if t == "T":
        return b"T"
    if t == "F":
        return b"F"
    if t == "i":
        return b"i" + int(v).to_bytes(1, "big", signed=True)
    if t == "U":
        return b"U" + int(v).to_bytes(1, "big", signed=False)
    if t == "I":
        return b"I" + int(v).to_bytes(2, "big", signed=True)
    if t == "l":
        return b"l" + int(v).to_bytes(4, "big", signed=True)
    if t == "d":
        return b"d" + struct.pack(">f", v)
    if t == "D":
        return b"D" + struct.pack(">d", v)
    if t == "C":
        return b"C" + v.encode("latin1")
    raise ValueError(t)


def _ubjson_string(v: str) -> bytes:
    """Length-prefixed string (the length is itself a UBJSON value)."""
    b = v.encode("latin1")
    return _ubjson_scalar(len(b)) + b


def ubjson_encode(obj) -> bytes:
    """Encode a python object exactly like @shelacek/ubjson (optimizeArrays=False).

    Note: object keys are written as length-prefixed strings WITHOUT a leading
    type marker (the S type is implied) - that is the library's convention.
    """
    out = bytearray()

    def enc(v):
        t = _ubjson_type(v)
        if t == "S":
            out.append(ord("S"))
            out.extend(_ubjson_string(v))
        elif t == "{":
            out.append(ord("{"))
            for k, val in v.items():
                out.extend(_ubjson_string(k))   # key: length + bytes, no S
                enc(val)                        # value: type marker + payload
            out.append(ord("}"))
        elif t == "[":
            out.append(ord("["))
            for e in v:
                enc(e)
            out.append(ord("]"))
        else:
            out.extend(_ubjson_scalar(v))

    enc(obj)
    return bytes(out)


# --------------------------------------------------------------------------
# capture decoding
# --------------------------------------------------------------------------


def _mac_from_adv(adv):
    """Extract the device MAC (hex, normal order) from a BLE advertisement."""
    for data in (adv.manufacturer_data or {}).values():
        if len(data) >= 8 and data[:2] == MFG_PREFIX:
            return data[2:8].hex()
    return None


def _pretty_mac(mac):
    """Format a 12-char hex MAC as AA:BB:CC:DD:EE:FF (upper case)."""
    if not mac or len(mac) != 12:
        return mac
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2)).upper()


def _is_pump(adv):
    """True if an advertisement looks like an OmniX device."""
    return bool(_mac_from_adv(adv)) or any(
        "fca5" in s.lower() for s in (adv.service_uuids or []))


async def resolve_pump(ident=None, timeout=8.0):
    """Find the pump and return (ble_address, mac_hex).

    `ident` is optional and may be a MAC (aa:bb:..), a CoreBluetooth UUID, a
    name substring, or None to just pick the pump.  The pump advertises its
    MAC in the manufacturer data `01 10 <mac6>`, so it is discovered, not
    hardcoded.
    """
    from bleak import BleakScanner
    ident = (ident or "").strip()
    looks_uuid = len(ident) >= 32 and ident.count("-") >= 4
    target = None
    if ident and not looks_uuid:
        try:
            target = bytes.fromhex(ident.replace(":", "").replace("-", ""))
        except ValueError:
            target = None

    print("scanning for the pump ...")
    devs = await BleakScanner.discover(timeout=timeout, return_adv=True)
    found = [(d.address, d, adv, _mac_from_adv(adv))
             for _addr, (d, adv) in devs.items() if _is_pump(adv)]
    if not found:
        raise SystemExit(
            "could not find the OmniX pump (in range? advertising?)")

    def matches(d, mac):
        mac_b = bytes.fromhex(mac) if mac else None
        return ((looks_uuid and d.address.lower() == ident.lower())
                or (target is not None and mac_b in (target, target[::-1]))
                or (ident and ident.lower() in (d.name or "").lower()))

    for addr, d, adv, mac in found:
        if matches(d, mac):
            return d.address, mac

    found.sort(key=lambda x: x[2].rssi, reverse=True)   # strongest first
    addr, d, adv, mac = found[0]
    print(f"  found {d.address} ({d.name}) mac={mac} rssi={adv.rssi}")
    return d.address, mac


async def ble_find_cmd_char(ident=None):
    """Scan, connect and return (client, characteristic, mac_hex)."""
    from bleak import BleakClient
    addr, mac_hex = await resolve_pump(ident)
    c = BleakClient(addr)
    await c.connect()
    target = None
    fallback = None
    for svc in c.services:
        if svc.uuid.lower() == SERVICE_UUID:
            for ch in svc.characteristics:
                if ch.uuid.lower() == CMD_CHAR_UUID:
                    target = ch
                if fallback is None:
                    fallback = ch
    if target is None:
        target = fallback
    if target is None:
        await c.disconnect()
        raise SystemExit("no vendor characteristic found")
    return c, target, mac_hex


async def ble_auth(c, ch, key):
    """Do the challenge/response and return the session id (8 bytes)."""
    await c.write_gatt_char(ch, b"\x06", response=True)
    challenge = bytes(await c.read_gatt_char(ch))
    if len(challenge) != 16:
        raise SystemExit(f"challenge is {len(challenge)} bytes, expected 16")
    await c.write_gatt_char(ch, b"\x06" + _aes_ecb_encrypt(key, challenge),
                            response=True)
    return challenge[:8]


async def ble_send(c, ch, key, session_id, fc, plaintext, read_reply=True,
                   timeout=3.0):
    """Send one encrypted command and (optionally) return the decrypted reply."""
    await c.write_gatt_char(ch, make_request(key, session_id, fc, plaintext),
                            response=True)
    if not read_reply:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        await asyncio.sleep(0.1)
        try:
            reply = bytes(await c.read_gatt_char(ch))
        except Exception:
            continue
        if len(reply) < FRAME_OVERHEAD:
            continue
        _fc, pt = open_reply(key, session_id, reply)
        if pt is not None:
            return pt
    return None


def build_plaintext(mac: str, cmdobj):
    """header(0x02) + 6-byte mac + UBJSON(cmdobj)."""
    mac_b = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    return b"\x02" + mac_b + ubjson_encode(cmdobj)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def cmd_scan(args):
    async def go():
        from bleak import BleakScanner
        devs = await BleakScanner.discover(timeout=args.timeout,
                                           return_adv=True)
        for addr, (d, adv) in devs.items():
            svcs = [s.lower() for s in (adv.service_uuids or [])]
            mac = _mac_from_adv(adv)
            pump = _is_pump(adv)
            if args.all or pump:
                mfg = {k: v.hex()
                       for k, v in (adv.manufacturer_data or {}).items()}
                tag = f"  <-- OmniX mac={_pretty_mac(mac)}" if pump else ""
                print(f"{d.address}  {d.name or '(none)':24s} rssi={adv.rssi:4d} "
                      f"svcs={svcs} mfg={mfg}{tag}")
    asyncio.run(go())


def build_speed_plaintext(mac: str, speed: int, tid: int) -> bytes:
    obj = {F_OPID: OPID_SET_FILTER_SPEED, F_SPEED: speed, F_TID: tid}
    return build_plaintext(mac, obj)


def build_telemetry_plaintext(mac: str, page: int = 0) -> bytes:
    return build_plaintext(mac, {F_OPID: OPID_GET_TELEMETRY, F_TELEM_ID: page})


def build_diagnostic_plaintext(mac: str, tid: int) -> bytes:
    return build_plaintext(mac, {F_OPID: OPID_GET_DIAGNOSTIC, F_TID: tid})


def format_rev(v):
    """Format a pump revision int (high 16 bits are (minor << 8) | major)."""
    if not isinstance(v, int):
        return None
    return f"{(v >> 16) & 0xFF}.{(v >> 24) & 0xFF}.0"


def parse_telemetry(pt: bytes):
    """Return (outer, inner) objects from a telemetry reply.

    The reply's `g` field is itself a UBJSON blob holding the telemetry data.
    """
    outer = ubjson_decode(pt[7:])
    g = outer.get("g") if isinstance(outer, dict) else None
    inner = outer
    if isinstance(g, (list, tuple, bytes, bytearray)):
        try:
            inner = ubjson_decode(bytes(g))
        except Exception:
            inner = outer
    elif isinstance(g, dict):
        inner = g
    return outer, inner


# The telemetry `V` array is [filterSpeed, lastSpeed, reportedSpeed, desiredSpeed]
# (from the app's getPumpSpeedsFromTelemetry).  We only need two of them.
V_FILTER_SPEED = 0          # the speed currently applied
V_LAST_SPEED = 1            # the last non-zero speed (used to turn back on)


def telemetry_speed(inner, index):
    """Return one entry of the telemetry speed array, or None."""
    v = inner.get("V") if isinstance(inner, dict) else None
    if isinstance(v, (list, tuple)) and index < len(v):
        return v[index]
    return None


def cmd_speed(args):
    key = parse_key(args.key)
    try:
        speed = int(args.value)
    except ValueError:
        raise SystemExit("speed must be an integer 0-100")
    if not 0 <= speed <= 100:
        raise SystemExit("speed must be between 0 and 100")
    tid = args.tid if args.tid is not None else random.randint(0, 32767)
    print(f"speed={speed} tid={tid}")
    if args.dry_run:
        pt = build_speed_plaintext(args.mac or "00:00:00:00:00:00", speed, tid)
        print(f"plaintext={pt.hex()}")
        return

    rsp = asyncio.run(run_command(
        args.mac, key, lambda m: build_speed_plaintext(m, speed, tid),
        args.fc))
    print_reply(rsp)


async def with_pump(ident, key, fn, fc=1):
    """Resolve/connect, authenticate, then run `fn(c, ch, sid, mac, fc)`."""
    c, ch, mac_hex = await ble_find_cmd_char(ident)
    try:
        sid = await ble_auth(c, ch, key)
        return await fn(c, ch, sid, mac_hex, fc)
    finally:
        await c.disconnect()


async def run_command(ident, key, make_pt, fc=1):
    """Connect, authenticate and send one command built by make_pt(mac)."""
    async def fn(c, ch, sid, mac, fc):
        return await ble_send(c, ch, key, sid, fc, make_pt(mac))

    return await with_pump(ident, key, fn, fc)


def print_reply(rsp):
    print("reply:", ubjson_decode(rsp[7:]) if rsp else None)


def cmd_diagnostics(args):
    """Read everything the app's Diagnostics screen shows."""
    key = parse_key(args.key)

    async def fn(c, ch, sid, mac, fc):
        tel = await ble_send(c, ch, key, sid, fc, build_telemetry_plaintext(mac, 0))
        diag = await ble_send(c, ch, key, sid, fc + 1,
                              build_diagnostic_plaintext(mac, random.randint(0, 32767)))
        return tel, diag

    tel, diag = asyncio.run(with_pump(args.mac, key, fn))
    if not tel and not diag:
        print("no reply (pump asleep / out of range?)")
        return

    outer, inner = parse_telemetry(tel) if tel else ({}, {})
    dobj = ubjson_decode(diag[7:]) if diag else {}

    if args.raw:
        print("telemetry:", json.dumps(outer, indent=2))
        print("diagnostics:", json.dumps(dobj, indent=2))
        return

    def d(name, default=None):
        return dobj.get(name, default) if isinstance(dobj, dict) else default

    speed = telemetry_speed(inner, V_FILTER_SPEED)
    p = d("p")
    revs = d("s")
    radio = format_rev(revs[0]) if isinstance(revs, list) and len(revs) > 0 else None
    drive = format_rev(revs[1]) if isinstance(revs, list) and len(revs) > 1 else None
    display = format_rev(inner.get("s")) if isinstance(inner, dict) else None

    rows = [
        ("Status", "running" if speed and speed > 0 else "paused"),
        ("Speed", f"{speed}%/{int(speed * PUMP_MAX_RPM / 100)} RPM" if speed is not None else "?"),
        ("Power", f"{p[0]} W" if isinstance(p, list) and len(p) > 0 else "?"),
        ("Air Temp", f"{d('a')} °F" if d("a") is not None else "?"),
        ("Drive Temp", f"{d('k')} °F" if d("k") is not None else "?"),
        ("Pump Drive Rev", drive or "?"),
        ("Radio Module Rev", radio or "?"),
        ("Display Rev", display or "?"),
    ]
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k + ':':<{width + 1}} {v}")


def cmd_off(args):
    key = parse_key(args.key)
    tid = random.randint(0, 32767)
    print(f"off: speed=0 tid={tid}")

    rsp = asyncio.run(run_command(
        args.mac, key, lambda m: build_speed_plaintext(m, 0, tid)))
    print_reply(rsp)


def cmd_on(args):
    """Turn the pump on, restoring its last non-zero speed (or --speed)."""
    key = parse_key(args.key)

    async def fn(c, ch, sid, mac, fc):
        speed = args.speed
        if speed is None:
            rsp = await ble_send(c, ch, key, sid, 1,
                                 build_telemetry_plaintext(mac, 0))
            if rsp:
                _, inner = parse_telemetry(rsp)
                for cand in (telemetry_speed(inner, V_LAST_SPEED),
                             telemetry_speed(inner, V_FILTER_SPEED)):
                    if cand:
                        speed = cand
                        break
        if not speed:
            raise SystemExit("pump reported no last speed; use --speed N")
        tid = random.randint(0, 32767)
        print(f"on: speed={speed} tid={tid} mac={mac}")
        return await ble_send(c, ch, key, sid, 2,
                              build_speed_plaintext(mac, speed, tid))

    print_reply(asyncio.run(with_pump(args.mac, key, fn)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    # shared by every command that talks to the pump
    conn = argparse.ArgumentParser(add_help=False)
    conn.add_argument("--mac", default=None,
                      help="MAC or CoreBluetooth UUID (auto-discovered if omitted)")
    conn.add_argument("--key", required=True,
                      help="16-byte security key (hex or UUID)")

    sc = sub.add_parser("scan", help="scan for the pump")
    sc.add_argument("--timeout", type=float, default=8.0)
    sc.add_argument("--all", action="store_true", help="show every device")
    sc.set_defaults(func=cmd_scan)

    sp = sub.add_parser("speed", parents=[conn], help="set the pump speed")
    sp.add_argument("value", help="speed percent, 0-100")
    sp.add_argument("--tid", type=int, default=None,
                    help="transaction id (default: random)")
    sp.add_argument("--fc", type=int, default=1)
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_speed)

    st = sub.add_parser("diagnostics", parents=[conn],
                        help="read pump diagnostics (speed, power, temps, revisions)")
    st.add_argument("--raw", action="store_true", help="show the raw messages")
    st.set_defaults(func=cmd_diagnostics)

    on = sub.add_parser("on", parents=[conn], help="turn the pump on")
    on.add_argument("--speed", type=int, default=None,
                    help="default: restore the pump's last speed")
    on.set_defaults(func=cmd_on)

    off = sub.add_parser("off", parents=[conn],
                         help="turn the pump off (speed 0)")
    off.set_defaults(func=cmd_off)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
