# EcoLife Local for Home Assistant

Cloud-free integration for **EcoLife** air quality sensors (ECL01). Home Assistant takes the place of
the EcoLife report server: the device is provisioned to send its data to Home Assistant instead of
`rest.ecolife.eu.com`. No EcoLife account or internet connection is needed.

## Installation

### HACS (custom repository)
1. HACS → ⋮ → *Custom repositories* → add `https://github.com/szupi-ipuzs/ecolife_ha_local`, category **Integration**.
2. Install **EcoLife Local** and restart Home Assistant.

### Manual
Copy `custom_components/ecolife_ha_local` into `<config>/custom_components/` and restart Home Assistant.

Then go to **Settings → Devices & services → Add integration → EcoLife Local**.

Requires Home Assistant 2025.8 or newer.

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
| device → HA, TCP | `P`/`Z` + base64(token) + base64(IV) + base64(AES-128-CBC(key, IV, JSON)) + `\n` (P-frames: plus `\x00` and 13 more bytes, 288 bytes total) |
| HA → device, after `P` | base64(AES-128-CBC(**soft-AP key**, IV of the P-frame, `OK` + 14 bytes)) |
| HA → device, after `Z` | `S` + base64(IV of the Z-frame) + base64(AES-128-CBC(key, same IV, command JSON padded)). The command is `{"cm":"NONE"}` when idle. `R` instead of `S` means "more commands follow": the device reports again within ~1 s to fetch the next one. |
| device → HA, **UDP**, every ~30 s | `D` + the same layout; payload is a JSON array of `{uuid, deviceTime, sequenceNo, measures: [{type, unit, value}]}`. No reply. |

Z-frames are device status (signal, LED brightness, firmware); their `tempc`/`dustMM`/`vocMM` fields are
not readings. The readings come from D-frames: `PRESSURE` in Pa (shown as hPa), `TEMP` °C, `HUMIDITY` %,
`VOC`, and `PM25`/`PM10` multiplied by 100. *Pollution level* uses the cloud's formula: the worse of
PM2.5/25 and PM10/50, in %.

The P-frame answer was derived from the cloud's answers in MITM captures: all of them decrypt to `OK…` this way.

## Status / known gaps

* LED control, using the commands captured from the cloud:
  * *LED brightness* (0–100 %, steps of 10): `{"cm":"BRIGHT","data":"40"}`. The value is a string.
  * *LED schedule start/end*: `{"cm":"BRIGHTIME","data":[start,end]}`.

  Like the cloud, any change sends both: `BRIGHT` in an `R` reply, then `BRIGHTIME` in an `S` reply.
  They go out with the device's next report (~20 s). The device reports its brightness, but not its
  schedule, so Home Assistant remembers the hours it sent.
* The server needs port 58300 for **both TCP and UDP**. When Home Assistant runs in Docker without
  host networking, publish `58300:58300/udp` as well.
* **Download diagnostics** contains the last 200 decrypted frames, for protocol research.

## Development

```bash
pip install pytest-homeassistant-custom-component
pytest
```

## Disclaimer

This is an independent, unofficial project. The author is not affiliated with,
endorsed by, or sponsored by Eco Life Sp. z o.o. "EcoLife" and related names
and logos are trademarks of their respective owners and are used here only to
identify the devices this integration works with. Use at your own risk.

## License

[MIT](LICENSE)
