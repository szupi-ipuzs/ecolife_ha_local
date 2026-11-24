"""LED brightness and schedule of EcoLife devices.

Commands captured from the cloud (sent in replies to Z-frames):

* ``{"cm": "BRIGHT", "data": "40"}``        brightness in %, as a string
* ``{"cm": "BRIGHTIME", "data": [6, 24]}``  LED lit from start to end hour

Whenever any LED setting changes the cloud sends both, BRIGHT first; we do the
same. The device reports its brightness ("bright") in every Z-frame, but not
its schedule, so the hours are remembered by Home Assistant.
"""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.number import (
    NumberEntity,
    NumberEntityDescription,
    NumberMode,
    RestoreNumber,
)
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import EcolifeLocalConfigEntry
from .const import CONF_TOKEN, DOMAIN, MANUFACTURER, MODEL, SUBENTRY_DEVICE
from .server import DeviceState, EcolifeServer

PARALLEL_UPDATES = 0

CMD_BRIGHT = "BRIGHT"
CMD_BRIGHT_TIME = "BRIGHTIME"

HOUR_DESCRIPTIONS = (
    NumberEntityDescription(
        key="led_start",
        translation_key="led_start",
        entity_category=EntityCategory.CONFIG,
        native_min_value=0,
        native_max_value=24,
        native_step=1,
        native_unit_of_measurement=UnitOfTime.HOURS,
        mode=NumberMode.SLIDER,
    ),
    NumberEntityDescription(
        key="led_stop",
        translation_key="led_stop",
        entity_category=EntityCategory.CONFIG,
        native_min_value=0,
        native_max_value=24,
        native_step=1,
        native_unit_of_measurement=UnitOfTime.HOURS,
        mode=NumberMode.SLIDER,
    ),
)
BRIGHTNESS_DESCRIPTION = NumberEntityDescription(
    key="led_brightness",
    translation_key="led_brightness",
    entity_category=EntityCategory.CONFIG,
    native_min_value=0,
    native_max_value=100,
    native_step=10,  # like the app's slider
    native_unit_of_measurement=PERCENTAGE,
    mode=NumberMode.SLIDER,
)


@dataclass
class LedSettings:
    """LED settings of one device, shared by its three number entities."""

    state: DeviceState
    start: int = 0
    stop: int = 24
    brightness: int | None = None  # last value we asked for

    @property
    def current_brightness(self) -> int | None:
        """Brightness being sent, otherwise the one the device reports."""
        if CMD_BRIGHT in self.state.pending and self.brightness is not None:
            return self.brightness
        reported = self.state.values.get("led_brightness")
        return int(reported) if reported is not None else self.brightness

    def send(self) -> None:
        """Queue BRIGHT (if known) and BRIGHTIME, in that order, like the cloud."""
        bright = self.current_brightness
        self.state.pending.pop(CMD_BRIGHT, None)
        self.state.pending.pop(CMD_BRIGHT_TIME, None)
        if bright is not None:
            self.state.queue_command({"cm": CMD_BRIGHT, "data": str(bright)})
        self.state.queue_command({"cm": CMD_BRIGHT_TIME, "data": [self.start, self.stop]})


async def async_setup_entry(
    hass: HomeAssistant,
    entry: EcolifeLocalConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """LED brightness and schedule per device."""
    server = entry.runtime_data
    for subentry in entry.subentries.values():
        if subentry.subentry_type != SUBENTRY_DEVICE:
            continue
        state = server.devices[subentry.data[CONF_TOKEN]]
        device_info = DeviceInfo(
            identifiers={(DOMAIN, state.token)},
            name=subentry.title,
            manufacturer=MANUFACTURER,
            model=MODEL,
        )
        led = LedSettings(state)
        entities: list[NumberEntity] = [
            EcolifeLedBrightness(server, led, device_info, BRIGHTNESS_DESCRIPTION)
        ]
        entities += [EcolifeLedHour(led, device_info, desc) for desc in HOUR_DESCRIPTIONS]
        async_add_entities(entities, config_subentry_id=subentry.subentry_id)


class _EcolifeLedEntity:
    _attr_has_entity_name = True
    _attr_should_poll = False

    def _setup(self, led: LedSettings, device_info: DeviceInfo, description: NumberEntityDescription) -> None:
        self.entity_description = description
        self._led = led
        self._attr_unique_id = f"{led.state.token}_{description.key}"
        self._attr_device_info = device_info


class EcolifeLedBrightness(_EcolifeLedEntity, NumberEntity):
    """LED brightness (reported by the device in every Z-frame)."""

    def __init__(
        self,
        server: EcolifeServer,
        led: LedSettings,
        device_info: DeviceInfo,
        description: NumberEntityDescription,
    ) -> None:
        """Initialise."""
        self._setup(led, device_info, description)
        self._server = server

    async def async_added_to_hass(self) -> None:
        """Follow the brightness the device reports."""
        self.async_on_remove(self._server.add_listener(self._led.state.token, self._on_frame))

    @callback
    def _on_frame(self) -> None:
        self.async_write_ha_state()

    @property
    def native_value(self) -> float | None:
        """Return the brightness."""
        return self._led.current_brightness

    async def async_set_native_value(self, value: float) -> None:
        """Send BRIGHT + BRIGHTIME with the device's next report (~20 s)."""
        self._led.brightness = int(round(value))
        self._led.state.pending.pop(CMD_BRIGHT, None)  # make current_brightness use the new value
        self._led.state.queue_command({"cm": CMD_BRIGHT, "data": str(self._led.brightness)})
        self._led.send()
        self.async_write_ha_state()


class EcolifeLedHour(_EcolifeLedEntity, RestoreNumber):
    """One end of the LED schedule (not reported by the device: remembered)."""

    def __init__(
        self, led: LedSettings, device_info: DeviceInfo, description: NumberEntityDescription
    ) -> None:
        """Initialise."""
        self._setup(led, device_info, description)

    async def async_added_to_hass(self) -> None:
        """Restore the last value."""
        await super().async_added_to_hass()
        last = await self.async_get_last_number_data()
        if last is not None and last.native_value is not None:
            setattr(self._led, self._field, int(last.native_value))

    @property
    def _field(self) -> str:
        return "start" if self.entity_description.key == "led_start" else "stop"

    @property
    def native_value(self) -> float:
        """Return the configured hour."""
        return getattr(self._led, self._field)

    async def async_set_native_value(self, value: float) -> None:
        """Send BRIGHT + BRIGHTIME with the device's next report (~20 s)."""
        setattr(self._led, self._field, int(round(value)))
        self._led.send()
        self.async_write_ha_state()
