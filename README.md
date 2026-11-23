# EcoLife Local for Home Assistant

Cloud-free integration for **EcoLife** air quality sensors (ECL01). Home Assistant takes the place of
the EcoLife report server: the device is provisioned to send its data to Home Assistant instead of
`rest.ecolife.eu.com`. No EcoLife account or internet connection is needed.

## How it works

* **Hub = local server.** Adding the integration starts a TCP server on port `58300` (configurable)
  inside Home Assistant.
* **Devices are added to the hub** with **Add device**:
  * **New device**: Home Assistant generates a token and an AES key, the same way the official app
    does. It then shows the command that provisions the device with them (see below).
  * **Already provisioned device**: enter the token and key the device was provisioned with. If an
    unknown device is already knocking on the server, its token is filled in for you.
* The device pushes data every ~20 s (`local_push`). It becomes unavailable after 2 minutes of silence.

## Provisioning a new device

The ECL01 only supports soft-AP pairing, so a computer with Wi-Fi does the provisioning:

1. In Home Assistant: the EcoLife Local hub → **Add device** → **New device**. Keep the dialog open.
2. Long-touch the top of the device until it enters pairing mode and opens the Wi-Fi network
   `ecolife-add-device`.
3. Connect the computer to `ecolife-add-device` and run (`pip install cryptography` first):

   ```bash
   python tools/provision_device.py --ssid HOME_WIFI --password SECRET \
       --host <Home Assistant IP> --port 58300 --token <token> --key <key>
   ```

   The dialog shows this command with your values filled in.
4. Reconnect the computer to your normal network and submit the dialog.

## Protocol (as implemented)

| Direction | Frame |
|---|---|
| device → HA | `P`/`Z` + base64(token) + base64(IV) + base64(AES-128-CBC(key, IV, JSON)) + `\n` (P-frames: plus `\x00` and 13 more bytes, 288 bytes total) |
| HA → device, after `P` | base64(AES-128-CBC(**soft-AP key**, IV of the P-frame, `OK` + 14 bytes)) |
| HA → device, after `Z` | `S` + base64(IV of the Z-frame) + base64(AES-128-CBC(key, same IV, `{"cm":"NONE"}` padded)) |

The P-frame answer was derived from the cloud's answers in MITM captures: all of them decrypt to `OK…` this way.

## Status / known gaps

* Telemetry has so far only been captured with placeholder values (`dustMM [-1,0]`,
  `tempc [135000,30000,300]`). Scaling of temperature, humidity and VOC follows the research bridge
  and **must be verified** with real readings. All conversions are in `protocol.interpret_telemetry`.
  The **Download diagnostics** file contains the raw decrypted frames to help with that.
* Pressure is not exposed: no captured frame contains it yet.
* LED brightness is only reported, not controllable: the S-frame command for it is not known yet.

## Development

```bash
pip install pytest-homeassistant-custom-component
pytest
```
