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
    interpret_measurements,
    interpret_telemetry,
    decrypt_json,
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
# D-frame payload, shaped like the captured UDP datagrams.
MEASURES = [
    {
        "uuid": "0000000000000000000000AA", "deviceTime": 1795477950, "sequenceNo": 2050,
        "measures": [
            {"type": "PRESSURE", "unit": "Pa", "value": 98745},
            {"type": "TEMP", "unit": "C", "value": 22},
            {"type": "VOC", "unit": "chwc", "value": 145},
            {"type": "HUMIDITY", "unit": "pc", "value": 42},
            {"type": "PM25", "unit": "ugm3", "value": 200},
            {"type": "PM10", "unit": "ugm3", "value": 300},
        ],
    }
]


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
    assert values == {"rssi": -33, "led_brightness": 50}


def test_measurements_scaling_and_trailing_junk() -> None:
    """D-frames: JSON array + '\n\x00' + junk; Pa -> hPa, PM / 100, cloud pollution index."""
    raw = json.dumps(MEASURES, separators=(",", ":")).encode() + b"\n\x00\xd6\xbf\x026"
    raw += b"\x00" * (-len(raw) % 16)
    iv = os.urandom(16)
    line = b"D" + base64.b64encode(TOKEN.encode()) + base64.b64encode(iv) + base64.b64encode(
        _aes_cbc(KEY, iv, raw, encrypt=True)
    )
    frame = parse_frame(line)
    assert frame.type == "D"
    payload = decrypt_json(frame, KEY)
    assert payload == MEASURES
    assert interpret_measurements(payload) == {
        "pressure": 987.45, "temperature": 22, "voc": 145, "humidity": 42,
        "pm25": 2.0, "pm10": 3.0, "pollution_level": 8,
    }
    # With a backlog the newest record (highest sequenceNo) wins.
    older = {**MEASURES[0], "sequenceNo": 2049, "measures": [{"type": "TEMP", "unit": "C", "value": 5}]}
    assert interpret_measurements([MEASURES[0], older])["temperature"] == 22


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

    z = encrypt_frame("Z", TOKEN, KEY, PLACEHOLDER)
    reply = await _send(port, z)
    assert reply.startswith(b"S") and len(reply) == 49
    zf = parse_frame(z)
    assert _aes_cbc(KEY, zf.iv, base64.b64decode(reply[25:]), encrypt=False).startswith(b'{"cm":"NONE"}')
    await hass.async_block_till_done()
    assert hass.states.get("number.living_room_led_brightness").state == "50"
    # Z-frames carry no readings: measurement sensors stay unavailable.
    assert hass.states.get("sensor.living_room_temperature").state == "unavailable"

    await _send_udp(port, encrypt_frame("D", TOKEN, KEY, MEASURES))
    await hass.async_block_till_done()
    assert hass.states.get("sensor.living_room_pm2_5").state == "2.0"
    assert hass.states.get("sensor.living_room_pm10").state == "3.0"
    assert hass.states.get("sensor.living_room_temperature").state == "22"
    assert hass.states.get("sensor.living_room_humidity").state == "42"
    assert hass.states.get("sensor.living_room_voc").state == "145"
    assert hass.states.get("sensor.living_room_atmospheric_pressure").state == "987.45"
    assert hass.states.get("sensor.living_room_pollution_level").state == "8"

    history = entry.runtime_data.devices[TOKEN].history
    assert [h["type"] for h in history] == ["P", "Z", "udp:D"]
    assert history[2]["payload"] == MEASURES

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
    suggested = {
        str(k): k.description["suggested_value"]
        for k in result["data_schema"].schema
        if k.description and "suggested_value" in k.description
    }
    assert suggested[CONF_TOKEN] == TOKEN

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
    assert result["description_placeholders"]["port"] == str(port)
    # The generated credentials are prefilled in editable fields.
    suggested = {
        str(field): field.description["suggested_value"]
        for field in result["data_schema"].schema
        if field.description and "suggested_value" in field.description
    }
    token, key = suggested[CONF_TOKEN], suggested[CONF_KEY]
    assert len(token) == 8 and token.isalnum() and len(base64.b64decode(key)) == 16

    # Invalid edits are rejected and the form is shown again.
    result = await hass.config_entries.subentries.async_configure(
        result["flow_id"], {"name": "Kitchen", CONF_TOKEN: "short", CONF_KEY: key}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {CONF_TOKEN: "invalid_token"}

    # Whatever is in the fields on submit is stored.
    result = await hass.config_entries.subentries.async_configure(
        result["flow_id"], {"name": "Kitchen", CONF_TOKEN: " edited00 ", CONF_KEY: key}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    sub = next(iter(entry.subentries.values()))
    assert sub.title == "Kitchen" and sub.data == {CONF_TOKEN: "edited00", CONF_KEY: key}
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


async def _send_udp(port: int, *datagrams: bytes) -> None:
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
    )
    for datagram in datagrams:
        transport.sendto(datagram)
    await asyncio.sleep(0.2)
    transport.close()


async def test_undecodable_datagrams(hass: HomeAssistant) -> None:
    """Datagrams that cannot be decoded are kept raw for diagnostics."""
    port = _free_port()
    entry = _entry(port)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    await _send_udp(port, b"\x01\x02 not a frame", encrypt_frame("D", TOKEN, os.urandom(16), MEASURES))
    await hass.async_block_till_done()

    server = entry.runtime_data
    assert server.devices[TOKEN].last_measurement is None
    assert len(server.raw_datagrams) == 2
    assert base64.b64decode(server.raw_datagrams[0]["base64"]) == b"\x01\x02 not a frame"
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_led_schedule_command(hass: HomeAssistant) -> None:
    """Changing the LED schedule sends BRIGHTIME once, with the next S-frame."""
    port = _free_port()
    entry = _entry(port)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("number.living_room_led_schedule_start").state == "0"
    assert hass.states.get("number.living_room_led_schedule_end").state == "24"

    for entity, value in (("number.living_room_led_schedule_start", 22), ("number.living_room_led_schedule_end", 6)):
        await hass.services.async_call(
            "number", "set_value", {"entity_id": entity, "value": value}, blocking=True
        )

    async def command_for_next_z() -> dict:
        z = encrypt_frame("Z", TOKEN, KEY, PLACEHOLDER)
        reply = await _send(port, z)
        plain = _aes_cbc(KEY, parse_frame(z).iv, base64.b64decode(reply[25:]), encrypt=False)
        return json.JSONDecoder().raw_decode(plain.decode("latin-1"))[0]

    # One command with both hours (the second change replaced the first), crossing midnight.
    assert await command_for_next_z() == {"cm": "BRIGHTIME", "data": [22, 6]}
    assert await command_for_next_z() == {"cm": "NONE"}
    assert entry.runtime_data.devices[TOKEN].last_command == {"cm": "BRIGHTIME", "data": [22, 6]}
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_led_brightness_command(hass: HomeAssistant) -> None:
    """Brightness: R-frame with BRIGHT (string), then S-frame with BRIGHTIME, like the cloud."""
    port = _free_port()
    entry = _entry(port)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    async def next_reply() -> tuple[bytes, dict]:
        z = encrypt_frame("Z", TOKEN, KEY, PLACEHOLDER)  # reports "bright": 50
        reply = await _send(port, z)
        plain = _aes_cbc(KEY, parse_frame(z).iv, base64.b64decode(reply[25:]), encrypt=False)
        return reply[:1], json.JSONDecoder().raw_decode(plain.decode("latin-1"))[0]

    assert await next_reply() == (b"S", {"cm": "NONE"})
    await hass.async_block_till_done()
    assert hass.states.get("number.living_room_led_brightness").state == "50"

    await hass.services.async_call(
        "number", "set_value", {"entity_id": "number.living_room_led_brightness", "value": 100}, blocking=True
    )
    # Shows the requested value while the command is pending.
    assert hass.states.get("number.living_room_led_brightness").state == "100"

    assert await next_reply() == (b"R", {"cm": "BRIGHT", "data": "100"})
    assert await next_reply() == (b"S", {"cm": "BRIGHTIME", "data": [0, 24]})
    assert await next_reply() == (b"S", {"cm": "NONE"})
    history = [h["type"] for h in entry.runtime_data.devices[TOKEN].history if h["type"] in ("R", "S")]
    assert history == ["R", "S"]
    assert await hass.config_entries.async_unload(entry.entry_id)
