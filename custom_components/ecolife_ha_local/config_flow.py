"""Config flow for EcoLife Local."""

from __future__ import annotations

import socket
from typing import Any

import voluptuous as vol

from homeassistant.components.network import async_get_source_ip
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    ConfigSubentryFlow,
    SubentryFlowResult,
)
from homeassistant.const import CONF_NAME, CONF_PORT
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector,
)

from .const import CONF_KEY, CONF_TOKEN, DEFAULT_PORT, DOMAIN, SUBENTRY_DEVICE
from .protocol import TOKEN_LENGTH, decode_key, generate_key, generate_token

PORT_SELECTOR = NumberSelector(
    NumberSelectorConfig(min=1, max=65535, step=1, mode=NumberSelectorMode.BOX)
)


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", port))
        except OSError:
            return False
    return True


class EcolifeLocalConfigFlow(ConfigFlow, domain=DOMAIN):
    """Create the local server (hub)."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose the TCP port devices will report to."""
        errors: dict[str, str] = {}
        if user_input is not None:
            port = int(user_input[CONF_PORT])
            self._async_abort_entries_match({CONF_PORT: port})
            if await self.hass.async_add_executor_job(_port_is_free, port):
                return self.async_create_entry(
                    title=f"EcoLife local server (port {port})", data={CONF_PORT: port}
                )
            errors[CONF_PORT] = "port_in_use"
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_PORT, default=DEFAULT_PORT): PORT_SELECTOR}
            ),
            errors=errors,
        )

    @classmethod
    @callback
    def async_get_supported_subentry_types(
        cls, config_entry: ConfigEntry
    ) -> dict[str, type[ConfigSubentryFlow]]:
        """Devices are subentries of the server."""
        return {SUBENTRY_DEVICE: DeviceSubentryFlow}


class DeviceSubentryFlow(ConfigSubentryFlow):
    """Add an EcoLife device to the server."""

    def __init__(self) -> None:
        """Pre-generate credentials for a new device."""
        self._token = generate_token()
        self._key = generate_key()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """New device (to provision) or one that already has a token and key."""
        return self.async_show_menu(
            step_id="user", menu_options=["new_device", "existing_device"]
        )

    async def async_step_new_device(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Show freshly generated credentials and how to provision the device."""
        if user_input is not None:
            return self._async_create(user_input[CONF_NAME], self._token, self._key)
        host = await async_get_source_ip(self.hass)
        port = self._get_entry().data[CONF_PORT]
        return self.async_show_form(
            step_id="new_device",
            data_schema=vol.Schema({vol.Required(CONF_NAME, default="EcoLife"): str}),
            description_placeholders={
                "host": host,
                "port": str(port),
                "token": self._token,
                "key": self._key,
                "command": (
                    f"python provision_device.py --ssid YOUR_WIFI --password YOUR_PASSWORD "
                    f"--host {host} --port {port} --token {self._token} --key {self._key}"
                ),
            },
        )

    async def async_step_existing_device(
        self, user_input: dict[str, Any] | None = None
    ) -> SubentryFlowResult:
        """Enter token and key of an already provisioned device."""
        errors: dict[str, str] = {}
        if user_input is not None:
            token = user_input[CONF_TOKEN].strip()
            key = user_input[CONF_KEY].strip()
            if len(token) != TOKEN_LENGTH or not token.isalnum():
                errors[CONF_TOKEN] = "invalid_token"
            try:
                decode_key(key)
            except ValueError:
                errors[CONF_KEY] = "invalid_key"
            if not errors:
                return self._async_create(user_input[CONF_NAME], token, key)

        # Suggest a token seen from an unknown device, if any.
        server = getattr(self._get_entry(), "runtime_data", None)
        seen = next(iter(getattr(server, "unknown_tokens", {}) or {}), "")
        schema = vol.Schema(
            {
                vol.Required(CONF_NAME, default="EcoLife"): str,
                vol.Required(CONF_TOKEN, default=seen): str,
                vol.Required(CONF_KEY): TextSelector(),
            }
        )
        return self.async_show_form(
            step_id="existing_device",
            data_schema=self.add_suggested_values_to_schema(schema, user_input),
            errors=errors,
        )

    @callback
    def _async_create(self, name: str, token: str, key: str) -> SubentryFlowResult:
        entry = self._get_entry()
        if any(
            sub.data.get(CONF_TOKEN) == token for sub in entry.subentries.values()
        ):
            return self.async_abort(reason="already_configured")
        return self.async_create_entry(
            title=name, data={CONF_TOKEN: token, CONF_KEY: key}, unique_id=token
        )
