"""Diagnostics for EcoLife Local (includes the raw decrypted frames)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import EcolifeLocalConfigEntry
from .const import CONF_KEY

TO_REDACT = {CONF_KEY, "MAC", "IP", "UUID", "uuid", "remote_ip"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: EcolifeLocalConfigEntry
) -> dict[str, Any]:
    """Return diagnostics."""
    server = entry.runtime_data
    return {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "port": server.port,
        "unknown_tokens": list(server.unknown_tokens),
        "undecoded_udp": async_redact_data(list(server.raw_datagrams), TO_REDACT),
        "devices": [
            async_redact_data(
                {
                    "token": state.token,
                    "last_seen": state.last_seen,
                    "last_registration": state.last_registration,
                    "remote_ip": state.remote_ip,
                    "registration": state.registration,
                    "telemetry": state.telemetry,
                    "measurements": state.measurements,
                    "last_measurement": state.last_measurement,
                    "values": state.values,
                    "pending_commands": list(state.pending.values()),
                    "last_command": state.last_command,
                    "history": list(state.history),
                },
                TO_REDACT,
            )
            for state in server.devices.values()
        ],
    }
