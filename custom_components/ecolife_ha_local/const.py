"""Constants for the EcoLife local integration."""

from __future__ import annotations

import logging
from typing import Final

DOMAIN: Final = "ecolife_ha_local"
LOGGER = logging.getLogger(__package__)

MANUFACTURER: Final = "EcoLife"
MODEL: Final = "ECL01"

DEFAULT_PORT: Final = 58300
SUBENTRY_DEVICE: Final = "device"
CONF_TOKEN: Final = "token"
CONF_KEY: Final = "key"

# Devices report every ~20 s; consider them offline after this many seconds.
OFFLINE_AFTER: Final = 120
