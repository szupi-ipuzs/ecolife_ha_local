"""EcoLife Local: Home Assistant acts as the report server of EcoLife sensors."""

from __future__ import annotations

from functools import partial

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PORT, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.typing import UNDEFINED

from .const import CONF_KEY, CONF_TOKEN, DOMAIN, SUBENTRY_DEVICE
from .protocol import decode_key
from .server import DeviceState, EcolifeServer

PLATFORMS: list[Platform] = [Platform.NUMBER, Platform.SENSOR]

type EcolifeLocalConfigEntry = ConfigEntry[EcolifeServer]


async def async_setup_entry(hass: HomeAssistant, entry: EcolifeLocalConfigEntry) -> bool:
    """Start the local server for all configured devices."""
    server = EcolifeServer(int(entry.data[CONF_PORT]))
    for subentry in entry.subentries.values():
        if subentry.subentry_type == SUBENTRY_DEVICE:
            server.add_device(
                subentry.data[CONF_TOKEN],
                decode_key(subentry.data[CONF_KEY]),
                subentry.subentry_id,
            )
    try:
        await server.async_start()
    except OSError as err:
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN,
            translation_key="port_unavailable",
            translation_placeholders={"port": str(server.port), "error": str(err)},
        ) from err

    entry.runtime_data = server
    entry.async_on_unload(
        server.add_registration_listener(partial(_async_update_device_info, hass, entry))
    )
    # Adding/removing a device (subentry) reloads the server.
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: EcolifeLocalConfigEntry) -> bool:
    """Stop the server."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.async_stop()
    return unloaded


async def _async_reload(hass: HomeAssistant, entry: EcolifeLocalConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


@callback
def _async_update_device_info(
    hass: HomeAssistant, entry: EcolifeLocalConfigEntry, state: DeviceState
) -> None:
    """Fill in device details from the registration (P) frame."""
    reg = state.registration or {}
    registry = dr.async_get(hass)
    device = registry.async_get_device_by_identifier((DOMAIN, state.token), entry.entry_id)
    if device is None:
        return
    connections = (
        {(dr.CONNECTION_NETWORK_MAC, dr.format_mac(reg["MAC"]))}
        if isinstance(reg.get("MAC"), str) and len(reg["MAC"]) == 12
        else None
    )
    registry.async_update_device(
        device.id,
        serial_number=reg.get("UUID") or device.serial_number,
        sw_version=reg.get("firmwareVersion") or device.sw_version,
        hw_version=", ".join(reg["sensors"]) if isinstance(reg.get("sensors"), list) else device.hw_version,
        new_connections=device.connections | connections if connections else UNDEFINED,
    )
