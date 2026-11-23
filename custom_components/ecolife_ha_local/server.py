"""Local replacement for the EcoLife report server."""

from __future__ import annotations

import asyncio
import base64
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging
from typing import Any

from homeassistant.util import dt as dt_util

from .protocol import (
    FRAME_MEASUREMENTS,
    FRAME_REGISTER,
    FRAME_TELEMETRY,
    Frame,
    ProtocolError,
    command_frame,
    decrypt_json,
    decrypt_payload,
    interpret_measurements,
    interpret_telemetry,
    parse_frame,
    register_reply,
)

_LOGGER = logging.getLogger(__name__)

READ_TIMEOUT = 10  # seconds to receive a frame
LINGER_TIMEOUT = 5  # seconds to wait for the device to close after our reply
MAX_FRAME = 4096
HISTORY_SIZE = 200  # decrypted frames kept for diagnostics (~1 h of telemetry)


@dataclass(slots=True)
class DeviceState:
    """What we know about one provisioned device."""

    token: str
    key: bytes
    subentry_id: str
    registration: dict[str, Any] | None = None
    telemetry: dict[str, Any] | None = None
    values: dict[str, float | None] = field(default_factory=dict)
    last_seen: datetime | None = None
    last_measurement: datetime | None = None
    last_registration: datetime | None = None
    remote_ip: str | None = None
    measurements: Any = None
    history: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=HISTORY_SIZE))


class EcolifeServer:
    """TCP server answering P- and Z-frames of known devices."""

    def __init__(self, port: int, host: str | None = None) -> None:
        """Initialise the server (call async_start to listen)."""
        self.port = port
        self.host = host
        self.devices: dict[str, DeviceState] = {}
        self._server: asyncio.base_events.Server | None = None
        self._listeners: dict[str, list[Callable[[], None]]] = {}
        self._registration_listeners: list[Callable[[DeviceState], None]] = []
        self.unknown_tokens: dict[str, str] = {}  # token -> remote ip
        self._udp: asyncio.DatagramTransport | None = None
        # UDP datagrams that could not be decoded (kept for diagnostics).
        self.raw_datagrams: deque[dict[str, Any]] = deque(maxlen=20)

    def add_device(self, token: str, key: bytes, subentry_id: str) -> DeviceState:
        """Register a device the server should answer."""
        state = DeviceState(token=token, key=key, subentry_id=subentry_id)
        self.devices[token] = state
        return state

    def add_listener(self, token: str, listener: Callable[[], None]) -> Callable[[], None]:
        """Call ``listener`` whenever the device sends a frame."""
        self._listeners.setdefault(token, []).append(listener)
        return lambda: self._listeners[token].remove(listener)

    def add_registration_listener(
        self, listener: Callable[[DeviceState], None]
    ) -> Callable[[], None]:
        """Call ``listener`` whenever a device sends a P-frame."""
        self._registration_listeners.append(listener)
        return lambda: self._registration_listeners.remove(listener)

    async def async_start(self) -> None:
        """Start listening (raises OSError if the port is taken)."""
        self._server = await asyncio.start_server(
            self._handle, host=self.host, port=self.port, limit=MAX_FRAME
        )
        _LOGGER.debug("Listening on %s", [s.getsockname() for s in self._server.sockets])
        # The device also sends a UDP datagram to the same port every ~30 s.
        try:
            self._udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _UdpProtocol(self), local_addr=(self.host or "0.0.0.0", self.port)
            )
        except OSError:
            await self.async_stop()
            raise

    async def async_stop(self) -> None:
        """Stop listening."""
        if self._udp:
            self._udp.close()
            self._udp = None
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        remote_ip = peer[0] if peer else "?"
        try:
            try:
                line = await asyncio.wait_for(reader.readuntil(b"\n"), READ_TIMEOUT)
            except asyncio.IncompleteReadError as err:
                line = err.partial
            reply = self.process(line, remote_ip)
            if reply is None:
                return
            writer.write(reply)
            await writer.drain()
            # Let the device read the reply and close first; also consumes the
            # bytes that follow a P-frame on the wire.
            try:
                async with asyncio.timeout(LINGER_TIMEOUT):
                    while await reader.read(MAX_FRAME):
                        pass
            except TimeoutError:
                pass
        except (TimeoutError, asyncio.LimitOverrunError, ConnectionError) as err:
            _LOGGER.debug("Connection from %s failed: %s", remote_ip, err)
        finally:
            writer.close()

    def process(self, line: bytes, remote_ip: str) -> bytes | None:
        """Handle one frame and return the bytes to send back (or None)."""
        try:
            frame = parse_frame(line)
        except ProtocolError as err:
            _LOGGER.debug("Ignoring data from %s: %s", remote_ip, err)
            return None
        if frame.type not in (FRAME_REGISTER, FRAME_TELEMETRY):
            _LOGGER.debug("Unexpected %s-frame over TCP from %s", frame.type, remote_ip)
            return None
        state = self._known_device(frame, remote_ip)
        if state is None:
            return None
        try:
            payload = decrypt_payload(frame, state.key)
        except ProtocolError as err:
            _LOGGER.warning("Cannot decrypt frame of device %s: %s", frame.token, err)
            return None
        return self._dispatch(state, frame, payload, remote_ip)

    def _known_device(self, frame: Frame, remote_ip: str) -> DeviceState | None:
        state = self.devices.get(frame.token)
        if state is None:
            if frame.token not in self.unknown_tokens:
                _LOGGER.warning(
                    "Frame from unknown EcoLife device (token %s) at %s; add it to the "
                    "EcoLife local server to accept it",
                    frame.token,
                    remote_ip,
                )
            self.unknown_tokens[frame.token] = remote_ip
            return None
        return state

    def process_datagram(self, data: bytes, remote_ip: str) -> None:
        """Handle a UDP datagram (format still being investigated: decode what we can)."""
        now = dt_util.utcnow()
        try:
            frame = parse_frame(data)
        except ProtocolError as err:
            self._keep_raw(data, remote_ip, str(err))
            return
        state = self._known_device(frame, remote_ip)
        if state is None:
            self._keep_raw(data, remote_ip, "unknown token")
            return
        try:
            payload = decrypt_json(frame, state.key)
        except ProtocolError as err:
            self._keep_raw(data, remote_ip, str(err))
            return
        _LOGGER.debug("UDP %s-frame from %s: %s", frame.type, state.token, payload)
        state.last_seen = now
        state.remote_ip = remote_ip
        state.history.append({"time": now.isoformat(), "type": f"udp:{frame.type}", "payload": payload})
        if frame.type == FRAME_MEASUREMENTS:
            values = interpret_measurements(payload)
            if values:
                state.measurements = payload
                state.last_measurement = now
                state.values.update(values)
        for listener in list(self._listeners.get(state.token, [])):
            listener()

    def _keep_raw(self, data: bytes, remote_ip: str, reason: str) -> None:
        _LOGGER.debug("Undecoded UDP datagram from %s (%s): %r", remote_ip, reason, data[:80])
        self.raw_datagrams.append(
            {
                "time": dt_util.utcnow().isoformat(),
                "remote_ip": remote_ip,
                "reason": reason,
                "length": len(data),
                "base64": base64.b64encode(data).decode(),
            }
        )

    def _dispatch(
        self, state: DeviceState, frame: Frame, payload: dict[str, Any], remote_ip: str
    ) -> bytes:
        now = dt_util.utcnow()
        state.last_seen = now
        state.history.append({"time": now.isoformat(), "type": frame.type, "payload": payload})
        state.remote_ip = remote_ip
        if frame.type == FRAME_REGISTER:
            _LOGGER.debug("Registration from %s: %s", state.token, payload)
            state.registration = payload
            state.last_registration = now
            reply = register_reply(frame)
            for reg_listener in list(self._registration_listeners):
                reg_listener(state)
        else:
            _LOGGER.debug("Telemetry from %s: %s", state.token, payload)
            state.telemetry = payload
            state.values.update(interpret_telemetry(payload))
            reply = command_frame(frame, state.key)
        for listener in list(self._listeners.get(state.token, [])):
            listener()
        return reply


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: EcolifeServer) -> None:
        self._server = server

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        self._server.process_datagram(data, str(addr[0]))
