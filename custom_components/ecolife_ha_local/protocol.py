"""EcoLife device <-> report-server wire protocol (no Home Assistant imports).

Device -> server, one frame per TCP connection, ASCII:

    <type> <base64(token)> <base64(IV)> <base64(AES-128-CBC(device key, IV, json))> "\\n"

* ``type`` is ``P`` (registration, sent once after boot/provisioning) or
  ``Z`` (telemetry, every ~20 s).
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
    r"^(?P<type>[PZ])"
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


def decrypt_payload(frame: Frame, key: bytes) -> dict[str, Any]:
    """Decrypt a frame's JSON payload with the device key."""
    plain = _aes_cbc(key, frame.iv, frame.ciphertext, encrypt=False)
    text = plain.decode("utf-8", errors="ignore")
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ProtocolError("decrypted payload is not JSON (wrong key?)")
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError as err:
        raise ProtocolError(f"decrypted payload is not JSON (wrong key?): {err}") from err
    if not isinstance(data, dict):
        raise ProtocolError("decrypted payload is not a JSON object")
    return data


def encrypt_frame(frame_type: str, token: str, key: bytes, payload: dict[str, Any]) -> bytes:
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
# Telemetry interpretation.
#
# Only placeholder telemetry has been captured so far
# (dustMM [-1, 0], vocMM [199, 892], tempc [135000, 30000, 300]), so these
# conversions follow the research bridge (ecolife_mqtt_bridge.py) and must be
# verified against real readings. Keep all scaling in this one function.
# --------------------------------------------------------------------------


def _item(data: dict[str, Any], key: str, index: int) -> float | None:
    value = data.get(key)
    if isinstance(value, list) and len(value) > index and isinstance(value[index], (int, float)):
        return float(value[index])
    return None


def interpret_telemetry(data: dict[str, Any]) -> dict[str, float | None]:
    """Convert a Z-frame payload into sensor values (None = not available)."""
    out: dict[str, float | None] = {}

    pm25, pm10 = _item(data, "dustMM", 0), _item(data, "dustMM", 1)
    # -1 is what the device reports while the dust sensor has no reading.
    out["pm25"] = pm25 if pm25 is not None and pm25 >= 0 else None
    out["pm10"] = pm10 if pm10 is not None and pm10 >= 0 and pm25 is not None and pm25 >= 0 else None

    # [135000, 30000, 300] is reported while no real reading is available.
    placeholder_tempc = data.get("tempc") == [135000, 30000, 300]
    temp_raw = None if placeholder_tempc else _item(data, "tempc", 0)
    if temp_raw is None:
        out["temperature"] = None
    elif temp_raw > 100000:
        out["temperature"] = round((temp_raw - 111500) / 1000, 1)
    else:
        out["temperature"] = round(temp_raw / 1000, 1)
    hum_raw = None if placeholder_tempc else _item(data, "tempc", 1)
    out["humidity"] = round(hum_raw / 1000, 1) if hum_raw is not None else None

    # vocMM[0] stayed at 199 in every frame captured so far: not trusted as VOC.
    voc_raw = _item(data, "vocMM", 0)
    if voc_raw == 199 and placeholder_tempc:
        voc_raw = None
    voc_mul = data.get("vocMul", 0.5)
    out["voc"] = (
        round(voc_raw * voc_mul, 1)
        if voc_raw is not None and isinstance(voc_mul, (int, float))
        else None
    )

    rssi = data.get("RSSI")
    out["rssi"] = float(rssi) if isinstance(rssi, (int, float)) else None
    bright = data.get("bright")
    out["led_brightness"] = float(bright) if isinstance(bright, (int, float)) else None
    return out
