"""Sensors for EcoLife Local (pushed by the device every ~20 s)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    EntityCategory,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.util import dt as dt_util

from . import EcolifeLocalConfigEntry
from .const import CONF_TOKEN, DOMAIN, MANUFACTURER, MODEL, OFFLINE_AFTER, SUBENTRY_DEVICE
from .server import DeviceState, EcolifeServer

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class EcolifeLocalSensorDescription(SensorEntityDescription):
    """Sensor fed from the device state."""

    value_fn: Callable[[DeviceState], float | str | datetime | None]
    needs_online: bool = True


def _value(key: str) -> Callable[[DeviceState], float | None]:
    return lambda state: state.values.get(key)


SENSORS: tuple[EcolifeLocalSensorDescription, ...] = (
    EcolifeLocalSensorDescription(
        key="pm25",
        device_class=SensorDeviceClass.PM25,
        native_unit_of_measurement=CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_fn=_value("pm25"),
    ),
    EcolifeLocalSensorDescription(
        key="pm10",
        device_class=SensorDeviceClass.PM10,
        native_unit_of_measurement=CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_fn=_value("pm10"),
    ),
    EcolifeLocalSensorDescription(
        key="temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=_value("temperature"),
    ),
    EcolifeLocalSensorDescription(
        key="humidity",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_fn=_value("humidity"),
    ),
    EcolifeLocalSensorDescription(
        key="voc",
        translation_key="voc",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_fn=_value("voc"),
    ),
    EcolifeLocalSensorDescription(
        key="rssi",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=_value("rssi"),
    ),
    EcolifeLocalSensorDescription(
        key="led_brightness",
        translation_key="led_brightness",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_value("led_brightness"),
    ),
    EcolifeLocalSensorDescription(
        key="ip_address",
        translation_key="ip_address",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        value_fn=lambda state: state.remote_ip,
    ),
    EcolifeLocalSensorDescription(
        key="last_seen",
        translation_key="last_seen",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda state: state.last_seen,
        needs_online=False,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: EcolifeLocalConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """One device (with its sensors) per device subentry."""
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
        async_add_entities(
            [EcolifeLocalSensor(server, state, device_info, desc) for desc in SENSORS],
            config_subentry_id=subentry.subentry_id,
        )


class EcolifeLocalSensor(SensorEntity):
    """A value reported by the device."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    entity_description: EcolifeLocalSensorDescription

    def __init__(
        self,
        server: EcolifeServer,
        state: DeviceState,
        device_info: DeviceInfo,
        description: EcolifeLocalSensorDescription,
    ) -> None:
        """Initialise the sensor."""
        self.entity_description = description
        self._server = server
        self._state = state
        self._attr_unique_id = f"{state.token}_{description.key}"
        self._attr_device_info = device_info

    async def async_added_to_hass(self) -> None:
        """Subscribe to frames and re-check availability periodically."""
        self.async_on_remove(self._server.add_listener(self._state.token, self._on_frame))
        self.async_on_remove(
            async_track_time_interval(self.hass, self._on_tick, timedelta(seconds=30))
        )

    @callback
    def _on_frame(self) -> None:
        self.async_write_ha_state()

    @callback
    def _on_tick(self, _now: datetime) -> None:
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Online if a frame arrived recently."""
        if not self.entity_description.needs_online:
            return True
        last = self._state.last_seen
        return last is not None and (dt_util.utcnow() - last).total_seconds() < OFFLINE_AFTER

    @property
    def native_value(self) -> float | str | datetime | None:
        """Return the value."""
        return self.entity_description.value_fn(self._state)
