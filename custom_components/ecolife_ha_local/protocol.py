"""EcoLife device <-> report-server wire protocol (no Home Assistant imports).

Device -> server, one frame per TCP connection, ASCII:

    <type> <base64(token)> <base64(IV)> <base64(AES-128-CBC(device key, IV, json))> "\\n"

* ``type`` is ``P`` (registration, sent once after boot/provisioning) or
  ``Z`` (status, every ~20 s), both over TCP, or ``D`` (measurements, every
  ~30 s, a UDP datagram to the same port; no reply expected). The D payload is a
  JSON array of ``{"uuid", "deviceTime", "sequenceNo", "measures": [{"type",
  "unit", "value"}]}`` records.
* The token is 8 characters, so its base64 is 12 chars ending in ``=``; the
  16-byte IV is 24 chars ending in ``==``; the ciphertext is zero padded.
* P-frames are always 288 bytes: the line above, ``\\x00`` and 13 bytes that
  follow on the wire. They are not needed to answer and are ignored.

Server -> device (same connection, no newline):

* P-frame: ``base64(AES-128-CBC(SOFT-AP key, IV of the P-frame, b"OK" + 14 bytes))``
* Z-frame: ``"S" + base64(IV of the Z-frame) +
  base64(AES-128-CBC(device key, same IV, json command padded to 16 bytes))``,
  where the command is ``{"cm":"NONE"}`` when there is nothing to do.

The SOFT-AP key/IV are hard-coded in the official app (add-device.js) and are
also used to encrypt the provisioning payload.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
import os
import re
import secrets
import string
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AP_KEY = base64.b64decode("Os8/3QWoxitwRGt6HaKDWA==")
AP_IV = base64.b64decode("QEhlaSRlbmJlcmdfUnUoJg==")

FRAME_REGISTER = "P"
FRAME_TELEMETRY = "Z"
COMMAND_NONE: dict[str, Any] = {"cm": "NONE"}

TOKEN_LENGTH = 8
KEY_LENGTH = 16

_FRAME_RE = re.compile(
    r"^(?P<type>[A-Z])"
    r"(?P<token>[A-Za-z0-9+/]+={0,2})"
    r"(?P<iv>[A-Za-z0-9+/]{22}==)"
    r"(?P<ct>[A-Za-z0-9+/]+={0,2})$"
)


class ProtocolError(Exception):
    """A frame could not be parsed or decrypted."""


@dataclass(frozen=True, slots=True)
class Frame:
    """A device frame (before decryption)."""

    type: str
    token: str
    iv: bytes
    ciphertext: bytes


def _aes_cbc(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


def parse_frame(line: bytes) -> Frame:
    """Parse the first line of a device frame (anything after ``\\n`` is ignored)."""
    text = line.split(b"\n", 1)[0].decode("ascii", errors="replace").strip()
    match = _FRAME_RE.match(text)
    if not match:
        raise ProtocolError(f"unrecognised frame: {text[:40]!r}")
    try:
        token = base64.b64decode(match["token"], validate=True).decode("ascii")
        iv = base64.b64decode(match["iv"], validate=True)
        ciphertext = base64.b64decode(match["ct"], validate=True)
    except (binascii.Error, UnicodeDecodeError) as err:
        raise ProtocolError(f"bad base64 in frame: {err}") from err
    if len(ciphertext) == 0 or len(ciphertext) % 16:
        raise ProtocolError(f"bad ciphertext length {len(ciphertext)}")
    return Frame(match["type"], token, iv, ciphertext)


def decrypt_json(frame: Frame, key: bytes) -> Any:
    """Decrypt a frame and return its JSON value (object or array)."""
    text = _aes_cbc(key, frame.iv, frame.ciphertext, encrypt=False).decode(
        "utf-8", errors="ignore"
    )
    starts = [i for i in (text.find("{"), text.find("[")) if i != -1]
    if not starts:
        raise ProtocolError("decrypted payload is not JSON (wrong key?)")
    try:
        value, _ = json.JSONDecoder().raw_decode(text, min(starts))
    except json.JSONDecodeError as err:
        raise ProtocolError(f"decrypted payload is not JSON (wrong key?): {err}") from err
    return value


def decrypt_payload(frame: Frame, key: bytes) -> dict[str, Any]:
    """Decrypt a P/Z frame, whose payload is a JSON object."""
    data = decrypt_json(frame, key)
    if not isinstance(data, dict):
        raise ProtocolError("decrypted payload is not a JSON object")
    return data


def encrypt_frame(frame_type: str, token: str, key: bytes, payload: Any) -> bytes:
    """Build a device frame (used by tests and tools to emulate a device)."""
    iv = os.urandom(16)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    raw += b"\x00" * (-len(raw) % 16)
    ct = _aes_cbc(key, iv, raw, encrypt=True)
    return (
        frame_type.encode()
        + base64.b64encode(token.encode())
        + base64.b64encode(iv)
        + base64.b64encode(ct)
        + b"\n"
    )


def register_reply(frame: Frame) -> bytes:
    """Answer to a P-frame, exactly like the EcoLife cloud."""
    block = b"OK" + os.urandom(14)
    return base64.b64encode(_aes_cbc(AP_KEY, frame.iv, block, encrypt=True))


def command_frame(frame: Frame, key: bytes, command: dict[str, Any] | None = None) -> bytes:
    """Answer to a Z-frame (S-frame) carrying ``command``."""
    raw = json.dumps(command or COMMAND_NONE, separators=(",", ":")).encode()
    raw += os.urandom(-len(raw) % 16)
    ct = _aes_cbc(key, frame.iv, raw, encrypt=True)
    return b"S" + base64.b64encode(frame.iv) + base64.b64encode(ct)


def generate_token() -> str:
    """8 alphanumeric characters, like randomToken(8) in the app."""
    alphabet = string.digits + string.ascii_uppercase + string.ascii_lowercase
    return "".join(secrets.choice(alphabet) for _ in range(TOKEN_LENGTH))


def generate_key() -> str:
    """16 random bytes, base64 encoded, like randomArray(16, 255) in the app."""
    return base64.b64encode(secrets.token_bytes(KEY_LENGTH)).decode()


def decode_key(key_b64: str) -> bytes:
    """Validate and decode a base64 device key."""
    try:
        key = base64.b64decode(key_b64.strip(), validate=True)
    except binascii.Error as err:
        raise ValueError("key is not valid base64") from err
    if len(key) != KEY_LENGTH:
        raise ValueError(f"key must be {KEY_LENGTH} bytes, got {len(key)}")
    return key


def provisioning_payload(
    *,
    ssid: str,
    password: str,
    report_host: str,
    report_port: int,
    key_b64: str,
    token: str,
    name: str = "EcoStation",
) -> bytes:
    """Encrypted soft-AP provisioning message (send to 192.168.4.1:6799)."""
    raw = json.dumps(
        {
            "name": name,
            "SSID": ssid,
            "password": password,
            "reportHost": report_host,
            "reportPort": report_port,
            "controlHost": report_host,
            "controlPort": report_port,
            "key": key_b64,
            "token": token,
        },
        separators=(",", ":"),
    ).encode()
    pad = 16 - len(raw) % 16
    raw += bytes([pad]) * pad  # PKCS#7, as CryptoJS does
    return base64.b64encode(_aes_cbc(AP_KEY, AP_IV, raw, encrypt=True))


def decrypt_provisioning_reply(reply: bytes, key_b64: str) -> dict[str, Any]:
    """The device answers provisioning with JSON encrypted with the NEW key and AP IV."""
    plain = _aes_cbc(
        decode_key(key_b64), AP_IV, base64.b64decode(reply.strip()), encrypt=False
    ).decode("utf-8", errors="ignore")
    return json.loads(plain[plain.find("{") : plain.rfind("}") + 1])


# --------------------------------------------------------------------------
# Interpretation.
# --------------------------------------------------------------------------

FRAME_MEASUREMENTS = "D"

# measure type -> (sensor key, factor). Scaling verified against the values the
# EcoLife cloud showed for the same device: PRESSURE is Pa (cloud shows hPa),
# PM values are sent multiplied by 100.
MEASURES: dict[str, tuple[str, float]] = {
    "PRESSURE": ("pressure", 0.01),
    "TEMP": ("temperature", 1),
    "HUMIDITY": ("humidity", 1),
    "VOC": ("voc", 1),
    "PM25": ("pm25", 0.01),
    "PM10": ("pm10", 0.01),
    "LIGHT": ("illuminance", 1),
}
PM25_NORM = 25.0  # µg/m³, used by the cloud for its "contamination" index
PM10_NORM = 50.0


def latest_record(data: Any) -> dict[str, Any] | None:
    """Pick the newest record of a D-frame (a list, possibly with backlog)."""
    records = [r for r in (data if isinstance(data, list) else [data]) if isinstance(r, dict)]
    if not records:
        return None
    return max(records, key=lambda r: r.get("sequenceNo", -1) if isinstance(r.get("sequenceNo"), int) else -1)


def interpret_measurements(data: Any) -> dict[str, float | None]:
    """Convert a D-frame payload into sensor values."""
    record = latest_record(data)
    out: dict[str, float | None] = {}
    if record is None:
        return out
    for measure in record.get("measures") or []:
        if not isinstance(measure, dict):
            continue
        mapping = MEASURES.get(str(measure.get("type")))
        value = measure.get("value")
        if mapping is None or not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        key, factor = mapping
        out[key] = round(value * factor, 2)
    pm25, pm10 = out.get("pm25"), out.get("pm10")
    if pm25 is not None or pm10 is not None:
        # Same formula as the cloud's CONTAMINATION value: worst PM as % of norm.
        out["pollution_level"] = round(
            max((pm25 or 0) / PM25_NORM, (pm10 or 0) / PM10_NORM) * 100
        )
    return out


def interpret_telemetry(data: dict[str, Any]) -> dict[str, float | None]:
    """Values from a Z-frame (status). Its tempc/dustMM/vocMM are not readings."""
    out: dict[str, float | None] = {}
    rssi = data.get("RSSI")
    out["rssi"] = float(rssi) if isinstance(rssi, (int, float)) else None
    bright = data.get("bright")
    out["led_brightness"] = float(bright) if isinstance(bright, (int, float)) else None
    return out
