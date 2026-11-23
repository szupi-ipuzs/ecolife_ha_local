#!/usr/bin/env python3
"""Provision an EcoLife device to report to Home Assistant (EcoLife Local).

1. Long-touch the top of the device until it enters pairing mode; it opens
   the Wi-Fi network "ecolife-add-device".
2. Connect this computer to "ecolife-add-device".
3. Run this tool with the values shown by Home Assistant (Add device -> New device):

   python provision_device.py --ssid HOME_WIFI --password SECRET \\
       --host 192.168.1.10 --port 58300 --token Ab12Cd34 --key BASE64KEY==

Requires: pip install cryptography
Exactly mirrors the soft-AP pairing of the official app (add-device.js).
"""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "custom_components" / "ecolife_ha_local"))
from protocol import (  # noqa: E402
    decode_key,
    decrypt_provisioning_reply,
    provisioning_payload,
)

DEVICE_IP = "192.168.4.1"
PING_PORT = 6899
DATA_PORT = 6799


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ssid", required=True, help="home Wi-Fi network name (2.4 GHz)")
    parser.add_argument("--password", required=True, help="home Wi-Fi password")
    parser.add_argument("--host", required=True, help="IP of Home Assistant as seen by the device")
    parser.add_argument("--port", type=int, default=58300, help="EcoLife Local server port")
    parser.add_argument("--token", required=True, help="8-character token from Home Assistant")
    parser.add_argument("--key", required=True, help="base64 key from Home Assistant")
    parser.add_argument("--device-ip", default=DEVICE_IP)
    args = parser.parse_args()

    try:
        decode_key(args.key)
    except ValueError as err:
        parser.error(str(err))
    if len(args.token) != 8:
        parser.error("token must be 8 characters")

    print(f"Checking device at {args.device_ip}:{PING_PORT} ...")
    try:
        with socket.create_connection((args.device_ip, PING_PORT), timeout=5) as ping:
            ping.settimeout(2)
            try:
                print("  device says:", ping.recv(64).decode(errors="replace").strip() or "(nothing)")
            except TimeoutError:
                pass
    except OSError as err:
        print(f"Device not reachable ({err}). Is this computer connected to 'ecolife-add-device'?")
        return 1
    time.sleep(1)

    payload = provisioning_payload(
        ssid=args.ssid,
        password=args.password,
        report_host=args.host,
        report_port=args.port,
        key_b64=args.key,
        token=args.token,
    )
    print(f"Sending Wi-Fi and server settings to {args.device_ip}:{DATA_PORT} ...")
    with socket.create_connection((args.device_ip, DATA_PORT), timeout=10) as data:
        data.sendall(payload)
        data.settimeout(15)
        reply = data.recv(2048)
    if not reply:
        print("Device closed the connection without answering.")
        return 1
    try:
        info = decrypt_provisioning_reply(reply, args.key)
    except Exception as err:  # noqa: BLE001
        print(f"Unexpected reply {reply!r}: {err}")
        return 1
    print("Device accepted the settings:", info)
    print(
        "Reconnect this computer to your normal network. The device now joins "
        f"'{args.ssid}' and reports to {args.host}:{args.port}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
