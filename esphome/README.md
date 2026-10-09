# ESPHome `omnix` component (ESP32-C3)

Controls a Hayward OmniX pump over BLE and exposes it to Home Assistant.

> Unofficial and unaffiliated with Hayward; use at your own risk (MIT — see the
> [root README](../README.md#license)).

## Requirements

- ESP32(-C3) — tested on an **ESP32-C3** (4 MB flash).
- ESPHome 2026.9+ (`pip install esphome`).
- The pump's 16-byte `security_key`.

## Setup

1. Copy `esphome/secrets.yaml.example` to `esphome/secrets.yaml` (gitignored)
   and fill it in. Everything except the pump fields is unique per install:

   ```sh
   openssl rand -base64 32   # -> api_key      (HA needs this one; also used for OTA)
   openssl rand -hex 8       # -> ap_password  (fallback AP)
   ```

   ```yaml
   wifi_ssid: "MyWifi"
   wifi_password: "..."
   api_key: "..."                         # paste into HA when adding
   ap_password: "..."
   pump_mac_address: "<your-pump-mac>"     # optional fallback (or "")
   ```

   The `api_key` is just a random value shared between the ESP32 and HA; it is
   not derived from the pump key or anything else. If you omit `pump_mac_address` (or
   set it to `""`), the device starts in discovery mode and you pick the pump
   from HA.

   **The pump `security_key` is optional here.** Setting `pump_security_key`
   compiles it into the firmware (like `api_key`); leave it `""` to instead
   enter it once from Home Assistant with the `Security Key` text entity, where
   the device stores it in its own flash (NVS).

2. Build/flash:

   ```sh
   esphome compile esphome/omnix-pump.yaml
   esphome upload  esphome/omnix-pump.yaml --device /dev/cu.usbmodemXXXX
   ```

   If you'd rather not put Wi-Fi in the file, flash as-is and connect to the
   fallback AP (`OmniX-Pump Fallback`); the captive portal opens automatically.
   The device is reachable at `http://omnix-pump.local`.

## Home Assistant

The device announces via mDNS, so HA's **ESPHome** integration should offer
it as a discovered device (name `omnix-pump`). When adding it, enter your
`api_key` from `secrets.yaml`.

### Entities

| Entity | What |
|---|---|
| `switch.omnix_pump_power` | on/off |
| `number.omnix_pump_speed` | speed slider 0–100 (%) |
| `text.omnix_pump_mac_address` | target MAC (editable, saved to flash) |
| `text.omnix_pump_security_key` | security key (masked, saved to flash; accepts hex with or without dashes) |
| `text_sensor.omnix_pump_speed` | reported speed, e.g. `50%/1725 RPM` |
| `text_sensor.omnix_pump_status` | `unknown` / `invalid-key` / `connecting` / `waiting` / `running` / `paused` / `not-a-pump` |
| `sensor.omnix_pump_power` | power draw (W) |
| `sensor.omnix_pump_air_temp` | air temperature (°F) |
| `sensor.omnix_pump_drive_temp` | drive temperature (°F) |
| `text_sensor.omnix_pump_pump_drive_rev` | pump drive revision (e.g. `17.0.0`) |
| `text_sensor.omnix_pump_radio_module_rev` | radio module revision (e.g. `2.3.0`) |
| `text_sensor.omnix_pump_display_rev` | display revision (e.g. `2.3.0`) |
| `text_sensor.omnix_pump_omnix_devices_found` | nearby OmniX devices: `MAC dev=.. stat=.. rssi=..` |

### Selecting a pump

1. Find your pump's MAC address, either:
   - in the Hayward OmniX app under **Settings → About Equipment** (shows the
     pump's Bluetooth/MAC address), or
   - in `text_sensor.omnix_pump_omnix_devices_found`, which lists every nearby
     OmniX device as `MAC dev=.. stat=.. rssi=..`.
2. Put the pump's MAC into `text.omnix_pump_mac_address`, and the key into
   `text.omnix_pump_security_key`.
3. The component connects and controls it. To go back to discovery, set the
   MAC text to empty — it will disconnect and list advertising devices again.

`on` restores the last non-zero speed; `off` sends speed 0. Both are the
component's behavior driven by the switch.

## How it works

Same protocol as `../utils/pump.py` (`../README.md`):

- discovers by scanning for the `FCA5` service / `0x0CEA` manufacturer data,
- writes `06`, reads a 16-byte challenge, replies with
  `AES-128-ECB(challenge, key)`,
- sends `0x07 || AES-128-GCM(pt, key, iv = fc || session) || fc || tag`
  where `pt = 0x02 || mac(6) || UBJSON`,
- decrypts replies using the reversed session id (a device quirk).

## Known limitations / TODO

- `text_sensor` status currently distinguishes `running` / `paused` /
  `unknown` / `connecting` / `waiting` / `not-a-pump`. The richer app states
  (`priming`, `stopped`, `freeze-protect`) need the telemetry state field
  (`IOT_PARAMS_STATE` / `WHYISON`) mapped — see the `TODO` in
  `components/omnix/omnix.cpp` (`process_telemetry_`).
- The `dev`/`stat` advertisement bytes are shown but their meaning per device
  type isn't confirmed (we only have a pump sample).
- `invalid-key` covers three cases: no key stored, an unparseable key, or a
  well-formed but wrong key. The first two come from `key_valid_`; the third is
  detected at runtime because the pump ACKs the auth write at the GATT level
  even with a wrong key, then never returns a decodable reply.
- Discovery/scanning is paused while connected (BLE can't scan and connect at
  once); clear the MAC to scan.
- `exclusive_ble: true` (opt-in) suspends Wi-Fi during each poll to hand the
  radio to BLE. ESPHome's `wifi::global_wifi_component->disable()` fully stops
  the driver (`esp_wifi_stop`), so Home Assistant loses the device for the
  duration of each window. On the tested ESP32-C3 the pump still did not
  complete the telemetry read, so this is off by default.
