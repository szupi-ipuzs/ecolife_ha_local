"""Tests for EcoLife Local."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
from unittest.mock import patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from homeassistant.config_entries import SOURCE_USER, ConfigEntryState, ConfigSubentryData
from homeassistant.const import CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr

from custom_components.ecolife_ha_local.const import CONF_KEY, CONF_TOKEN, DOMAIN, SUBENTRY_DEVICE
from custom_components.ecolife_ha_local.protocol import (
    AP_IV,
    AP_KEY,
    _aes_cbc,
    command_frame,
    decrypt_payload,
    decrypt_provisioning_reply,
    encrypt_frame,
    interpret_telemetry,
    parse_frame,
    provisioning_payload,
    register_reply,
)

TOKEN = "Ab12Cd34"
KEY_B64 = base64.b64encode(bytes(range(16))).decode()
KEY = bytes(range(16))

# These tests run a real TCP server on 127.0.0.1.
pytestmark = pytest.mark.usefixtures("socket_enabled")

REGISTRATION = {
    "UUID": "0000000000000000000000AA",
    "model": "HONYWELL",
    "MAC": "AABBCCDDEEFF",
    "firmwareVersion": "0.12.7",
    "sensors": ["MPL3115", "HTS221", "HPMA115S0", "CCS801"],
    "token": TOKEN,
}
PLACEHOLDER = {
    "UUID": "0000000000000000000000AA", "IP": "192.168.2.221", "V5": 4924, "RSSI": -33,
    "bright": 50, "presscomp": 0, "heater": 53, "hpmauc": 100, "vocMul": 0.5,
    "dustMM": [-1, 0], "vocMM": [199, 892], "color": [87, 177, 8],
    "tempc": [135000, 30000, 300], "stmFwVer": "000C07", "stmBootVer": "000600", "espFwVer": "01000B",
}
REAL = {**PLACEHOLDER, "dustMM": [12, 18], "tempc": [21300, 44100, 300]}


def p_frame() -> bytes:
    """A P-frame as the device sends it: line, NUL and 13 more bytes (288 bytes total)."""
    line = encrypt_frame("P", TOKEN, KEY, REGISTRATION)
    return line + b"\x00" + b"bmxooYwGYJpKf"


# --- protocol ---------------------------------------------------------------


def test_register_reply_is_ok_encrypted_with_ap_key() -> None:
    """The P-frame answer decrypts to OK with the soft-AP key and the frame IV."""
    frame = parse_frame(p_frame())
    assert frame.type == "P" and frame.token == TOKEN
    assert decrypt_payload(frame, KEY) == REGISTRATION
    reply = register_reply(frame)
    assert len(reply) == 24 and not reply.endswith(b"\n")
    assert _aes_cbc(AP_KEY, frame.iv, base64.b64decode(reply), encrypt=False)[:2] == b"OK"


def test_command_frame_layout() -> None:
    """S-frame = 'S' + echoed IV + encrypted command, like the cloud (49 bytes for NONE)."""
    frame = parse_frame(encrypt_frame("Z", TOKEN, KEY, PLACEHOLDER))
    s = command_frame(frame, KEY)
    assert len(s) == 49 and s[:1] == b"S"
    assert base64.b64decode(s[1:25]) == frame.iv
    plain = _aes_cbc(KEY, frame.iv, base64.b64decode(s[25:]), encrypt=False)
    assert plain.startswith(b'{"cm":"NONE"}')


def test_provisioning_payload_roundtrip() -> None:
    """Provisioning JSON is compact, PKCS#7 padded and encrypted with the app key/IV."""
    data = provisioning_payload(
        ssid="Home", password="pw", report_host="192.168.1.10", report_port=58300,
        key_b64=KEY_B64, token=TOKEN,
    )
    plain = _aes_cbc(AP_KEY, AP_IV, base64.b64decode(data), encrypt=False)
    plain = plain[: -plain[-1]]
    assert json.loads(plain) == {
        "name": "EcoStation", "SSID": "Home", "password": "pw",
        "reportHost": "192.168.1.10", "reportPort": 58300,
        "controlHost": "192.168.1.10", "controlPort": 58300,
        "key": KEY_B64, "token": TOKEN,
    }
    assert b" " not in plain
    device_reply = base64.b64encode(
        _aes_cbc(KEY, AP_IV, b'{"UUID":"X","status":"OK"}' + b"\x00" * 6, encrypt=True)
    )
    assert decrypt_provisioning_reply(device_reply, KEY_B64) == {"UUID": "X", "status": "OK"}


def test_interpret_placeholder_telemetry() -> None:
    """Placeholder readings (dust -1) give no PM values."""
    values = interpret_telemetry(PLACEHOLDER)
    assert values["pm25"] is None and values["pm10"] is None
    assert values["rssi"] == -33 and values["led_brightness"] == 50


# --- Home Assistant -----------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _entry(port: int, with_device: bool = True) -> MockConfigEntry:
    subentries = (
        [ConfigSubentryData(data={CONF_TOKEN: TOKEN, CONF_KEY: KEY_B64}, subentry_type=SUBENTRY_DEVICE,
                            title="Living room", unique_id=TOKEN)]
        if with_device else []
    )
    return MockConfigEntry(domain=DOMAIN, data={CONF_PORT: port}, subentries_data=subentries)


async def _send(port: int, data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    reply = await asyncio.wait_for(reader.read(1024), 5)
    writer.close()
    await writer.wait_closed()
    return reply


async def test_user_flow(hass: HomeAssistant) -> None:
    """The hub asks for a port."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    with patch("custom_components.ecolife_ha_local.config_flow._port_is_free", return_value=False):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_PORT: 58300})
    assert result["errors"] == {CONF_PORT: "port_in_use"}
    port = _free_port()
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {CONF_PORT: port})
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {CONF_PORT: port}
    entry = result["result"]
    assert entry.state is ConfigEntryState.LOADED
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_end_to_end(hass: HomeAssistant) -> None:
    """Device registers, gets OK, sends telemetry, gets S-frame; sensors update."""
    port = _free_port()
    entry = _entry(port)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("sensor.living_room_pm2_5").state == "unavailable"

    data = p_frame()
    reply = await _send(port, data)
    iv = parse_frame(data).iv
    assert _aes_cbc(AP_KEY, iv, base64.b64decode(reply), encrypt=False)[:2] == b"OK"
    await hass.async_block_till_done()

    device = dr.async_get(hass).async_get_device_by_identifier((DOMAIN, TOKEN), entry.entry_id)
    assert device.serial_number == "0000000000000000000000AA"
    assert device.sw_version == "0.12.7"
    assert (dr.CONNECTION_NETWORK_MAC, "aa:bb:cc:dd:ee:ff") in device.connections

    z = encrypt_frame("Z", TOKEN, KEY, REAL)
    reply = await _send(port, z)
    assert reply.startswith(b"S") and len(reply) == 49
    zf = parse_frame(z)
    assert _aes_cbc(KEY, zf.iv, base64.b64decode(reply[25:]), encrypt=False).startswith(b'{"cm":"NONE"}')
    await hass.async_block_till_done()

    assert hass.states.get("sensor.living_room_pm2_5").state == "12.0"
    assert hass.states.get("sensor.living_room_pm10").state == "18.0"
    assert hass.states.get("sensor.living_room_temperature").state == "21.3"
    assert hass.states.get("sensor.living_room_humidity").state == "44.1"
    assert hass.states.get("sensor.living_room_led_brightness").state == "50.0"

    # Placeholder telemetry -> PM unknown, but device still online
    await _send(port, encrypt_frame("Z", TOKEN, KEY, PLACEHOLDER))
    await hass.async_block_till_done()
    assert hass.states.get("sensor.living_room_pm2_5").state == "unknown"

    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_unknown_device_and_wrong_key(hass: HomeAssistant) -> None:
    """Unknown tokens get no answer and are offered when adding a device."""
    port = _free_port()
    entry = _entry(port, with_device=False)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert await _send(port, p_frame()) == b""
    assert TOKEN in entry.runtime_data.unknown_tokens

    result = await hass.config_entries.subentries.async_init(
        (entry.entry_id, SUBENTRY_DEVICE), context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.MENU
    result = await hass.config_entries.subentries.async_configure(
        result["flow_id"], {"next_step_id": "existing_device"}
    )
    assert result["type"] is FlowResultType.FORM
    schema_defaults = {str(k): k.default() for k in result["data_schema"].schema if hasattr(k, "default") and callable(k.default)}
    assert schema_defaults[CONF_TOKEN] == TOKEN

    result = await hass.config_entries.subentries.async_configure(
        result["flow_id"], {"name": "Bedroom", CONF_TOKEN: TOKEN, CONF_KEY: "bad"}
    )
    assert result["errors"] == {CONF_KEY: "invalid_key"}
    result = await hass.config_entries.subentries.async_configure(
        result["flow_id"], {"name": "Bedroom", CONF_TOKEN: TOKEN, CONF_KEY: KEY_B64}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()

    # The entry reloaded with the new device; it is answered now.
    assert entry.state is ConfigEntryState.LOADED
    data = p_frame()
    reply = await _send(port, data)
    assert _aes_cbc(AP_KEY, parse_frame(data).iv, base64.b64decode(reply), encrypt=False)[:2] == b"OK"

    # A frame encrypted with another key is ignored.
    other = encrypt_frame("Z", TOKEN, os.urandom(16), PLACEHOLDER)
    assert await _send(port, other) == b""
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_new_device_flow(hass: HomeAssistant) -> None:
    """New device: credentials are generated and shown with the provisioning command."""
    port = _free_port()
    entry = _entry(port, with_device=False)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.subentries.async_init(
        (entry.entry_id, SUBENTRY_DEVICE), context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.subentries.async_configure(
        result["flow_id"], {"next_step_id": "new_device"}
    )
    ph = result["description_placeholders"]
    assert len(ph["token"]) == 8 and len(base64.b64decode(ph["key"])) == 16
    assert f"--port {port}" in ph["command"] and ph["token"] in ph["command"]
    result = await hass.config_entries.subentries.async_configure(result["flow_id"], {"name": "Kitchen"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    sub = next(iter(entry.subentries.values()))
    assert sub.title == "Kitchen" and sub.data == {CONF_TOKEN: ph["token"], CONF_KEY: ph["key"]}
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_port_taken(hass: HomeAssistant) -> None:
    """If the port is busy, setup is retried."""
    with socket.socket() as busy:
        busy.bind(("0.0.0.0", 0))
        busy.listen()
        port = busy.getsockname()[1]
        entry = _entry(port)
        entry.add_to_hass(hass)
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.SETUP_RETRY
