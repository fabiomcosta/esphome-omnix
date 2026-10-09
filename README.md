# Hayward OmniX control (ESPHome + Home Assistant or CLI)

> **Unofficial and unaffiliated.** This project is not affiliated with,
> endorsed by, or supported by Hayward. "Hayward" and "OmniX" are trademarks
> of their respective owners, used here only to describe compatibility. It was
> reverse-engineered for personal interoperability — use it at your own risk
> (see [License](#license)).

Control the Hayward OmniX filter pump **you own**, **locally** over BLE — no
phone app, no cloud, and nothing leaves your network. Read its diagnostics and
control it from Home Assistant or the command line. There are two ways to use
this project:

- **ESPHome + Home Assistant** (the main one): flash an ESP32 (e.g. an ESP32-C3)
  and HA gets an on/off switch, a speed control, and all the diagnostics the
  pump reports — power, temperatures, speed, and more.
- **Command line** (`utils/pump.py`): talk to the pump directly from any
  BLE-capable machine (your laptop, a Raspberry Pi, ...). Handy for testing, for
  machines without ESPHome, and for grabbing the pump's MAC address.

Both need the pump's **`securityKey`** — a per-pump 16-byte key written to the
pump when you set it up in the Hayward app. Bring your own key (see
[Getting your securityKey](#2-get-your-securitykey)).

---

## Home Assistant (ESPHome)

### What you get

Once flashed, Home Assistant exposes:

| Entity                                       | What                                                                                       |
| -------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `switch.omnix_pump_power`                    | On/off (turning on restores the last speed)                                                |
| `number.omnix_pump_speed`                    | Speed slider, 0–100 %                                                                      |
| `text_sensor.omnix_pump_speed`               | Reported speed, e.g. `50%/1725 RPM`                                                        |
| `text_sensor.omnix_pump_status`              | `running` / `paused` / `unknown` / `connecting` / `waiting` / `invalid-key` / `not-a-pump` |
| `sensor.omnix_pump_power`                    | Power draw (W)                                                                             |
| `sensor.omnix_pump_air_temp`                 | Air temperature (°F)                                                                       |
| `sensor.omnix_pump_drive_temp`               | Drive temperature (°F)                                                                     |
| `text_sensor.omnix_pump_pump_drive_rev`      | Pump drive revision (e.g. `17.0.0`)                                                        |
| `text_sensor.omnix_pump_radio_module_rev`    | Radio module revision (e.g. `2.3.0`)                                                       |
| `text_sensor.omnix_pump_display_rev`         | Display revision (e.g. `2.3.0`)                                                            |
| `text_sensor.omnix_pump_omnix_devices_found` | Nearby OmniX devices (used to find your pump's MAC)                                        |
| `text.omnix_pump_mac_address`                | Target pump MAC (editable)                                                                 |
| `text.omnix_pump_security_key`               | Security key (masked, stored on the device)                                                |

### Requirements

- An ESP32 board — tested on an **ESP32-C3** (4 MB flash). Any ESP32 should
  work; ESP32-S3 / classic ESP32 have more headroom for Wi-Fi + BLE.
- [ESPHome](https://esphome.io) 2026.9+ (`pip install esphome`).
- Your pump's `securityKey` (see below).

### 1. Flash your ESP32

From the repo:

```sh
cd esphome
cp secrets.yaml.example secrets.yaml
```

Fill in `secrets.yaml` (it's gitignored). Everything except the pump fields is
unique to your install:

```sh
openssl rand -base64 32   # -> api_key      (shared with Home Assistant)
openssl rand -hex 8       # -> ap_password  (fallback Wi-Fi AP)
```

```yaml
wifi_ssid: 'MyWifi'
wifi_password: '...'
api_key: '...' # paste this into HA when adding the device
ap_password: '...'
pump_mac_address: '' # optional; blank = pick the pump from HA
pump_security_key: '' # optional; blank = set it from HA
```

> **The pump fields are optional.** Setting `pump_mac_address` and/or
> `pump_security_key` here bakes them into the firmware (exactly like
> `api_key`), which is handy for provisioning. Leave them `''` to instead pick
> the MAC and enter the key from Home Assistant; the key is then stored in the
> device's own flash (NVS). See [Get your securityKey](#2-get-your-securitykey).

Then build and flash:

```sh
esphome compile omnix-pump.yaml
esphome upload  omnix-pump.yaml --device /dev/cu.usbmodemXXXX
```

`/dev/cu.usbmodemXXXX` is the USB serial port of your board (on macOS,
`ls /dev/cu.usb*`). If you'd rather not put Wi-Fi in the file, flash as-is and
connect to the fallback AP (`OmniX-Pump Fallback`) — the captive portal opens
automatically. The device is reachable at `http://omnix-pump.local` (mDNS; it
also answers on ESPHome's default `192.168.4.1` while on the fallback AP).

See [`esphome/README.md`](esphome/README.md) for more detail.

### 2. Get your securityKey

Every pump has its own 16-byte `securityKey`, written to the pump when you set
it up in the Hayward OmniX app. **You need it** — without it the pump rejects
every command. This project does not include any tooling to obtain it; bring
your own key.

Supply it in either of two ways:

* **Home Assistant (default, key-free firmware):** paste it into the
  `Security Key` entity after adding the device (step 4). The ESP32 stores it
  in its own flash, so it never ends up in the config or the `.bin`.
* **Build-time provisioning:** set `pump_security_key` in
  `esphome/secrets.yaml` and rebuild. It is then compiled into the firmware
  binary (exactly like `api_key`) — only do this if you won't share the `.bin`.

Keep the key private — it can control your pump.

### 3. Find your pump's MAC address

The pump's BLE address can be found any of these ways:

- **In the Hayward OmniX app** — open **Settings → About Equipment**, which
  shows the pump's Bluetooth/MAC address.
- **In Home Assistant** — the `OmniX Devices Found` sensor lists nearby OmniX
  devices as `MAC dev=.. stat=.. rssi=..`; leave `MAC Address` empty and the
  component scans and reports them.
- **From a laptop** — run the CLI scan (see
  [Command line](#command-line-utilspumpy) below), which prints, e.g.:

  ```sh
  $ .venv/bin/python utils/pump.py scan
  ABCD1234-...  MyPump_001122334455  rssi=-79 ...  <-- OmniX mac=AA:BB:CC:DD:EE:FF
  ```

### 4. Add the device to Home Assistant

The ESP32 announces itself over mDNS as `omnix-pump`, so Home Assistant's
**ESPHome** integration should offer it as a discovered device. When adding it,
enter the `api_key` you generated above.

Then configure the pump from the device page:

- **MAC Address** → the BLE MAC you found above (in `AA:BB:CC:DD:EE:FF` form).
  To go back to discovery, clear the field.
- **Security Key** → paste your `securityKey` (skip this if you set
  `pump_security_key` in `secrets.yaml`).

---

## Command line (`utils/pump.py`)

`pump.py` talks to the pump directly over BLE from any machine with Python and
[bleak](https://github.com/hbldh/bleak) — macOS, Linux, Windows. It's the
easiest way to test the connection, grab a MAC address, or control the pump
without Home Assistant.

```sh
python3 -m venv .venv
./.venv/bin/pip install -r utils/requirements.txt

KEY=<your-16-byte-securityKey>

./.venv/bin/python utils/pump.py diagnostics --key $KEY
./.venv/bin/python utils/pump.py speed  --key $KEY 50    # raw speed percent, 0-100
./.venv/bin/python utils/pump.py on     --key $KEY       # restore last speed
./.venv/bin/python utils/pump.py off    --key $KEY       # speed 0
```

`diagnostics` prints everything the pump's screen shows:

```
Status:           running
Speed:            50%/1725 RPM
Power:            256 W
Air Temp:         89 °F
Drive Temp:       37 °F
Pump Drive Rev:   17.0.0
Radio Module Rev: 2.3.0
Display Rev:      2.3.0
```

`--mac` is **optional**: the pump is auto-discovered by scanning for its `FCA5`
service / manufacturer data, and its MAC is read from the advertisement
(`01 10 <mac6>`) — nothing is hardcoded. You can still pass `--mac` (a MAC or a
CoreBluetooth UUID) to target a specific pump if several are nearby.

### Commands

```
scan                        list devices; the pump shows its discovered MAC
diagnostics --key K [--raw] [--mac M]
speed   --key K 0-100 [--mac M]
on      --key K [--speed N] [--mac M]
off     --key K [--mac M]
```

`--raw` dumps the raw UBJSON for the telemetry and diagnostics messages. `on`
restores the last non-zero speed (`--speed N` to force one); `off` sends speed
`0`. There are no app presets — speed is the raw percentage the pump uses.

---

## Technical

### Protocol (recovered from the `com.hayward.omniflex` app)

- Service `0000fca5-0000-1000-8000-00805f9b34fb`, one command/response
  characteristic `66460130-8759-9bf8-b4db-7b04b9b026f1`.
- **Auth**: write `06` → read 16-byte challenge → write
  `06 || AES-128-ECB(challenge, securityKey)`; `session.id = challenge[:8]`.
- **Requests**: `07 || AES-128-GCM(pt, key, iv = fc_be32 || session.id)` where
  `pt = 0x02 || mac(6) || UBJSON(CmdObj)` and the wire ends with
  `... || fc(4) || authTag(16)`.
- **Replies**: `ciphertext || fc(4) || authTag(16)`, but encrypted with
  `iv = fc || reversed(session.id)` (the app reverses it in
  `SecureMessageDecrypt`).
- UBJSON is the `@shelacek/ubjson` dialect. CmdObj keys are single characters:

| key    | meaning           | notes                                                                  |
| ------ | ----------------- | ---------------------------------------------------------------------- |
| `\x03` | OPID              | `9` = set filter speed, `386` = get diagnostics, `600` = get telemetry |
| `v`    | speed             | percent                                                                |
| `\x04` | transaction id    | request TID, echoed as `\x05` in the reply                             |
| `G`    | telemetry page id | request; `0`/`1`                                                       |

**Telemetry** (OPID `600` → reply `1600`): outer `{\x03:1600, ..., g:<bytes>}`;
`g` is another UBJSON blob. Relevant inner fields: `V`, a 4-element speed array
`[filterSpeed, lastSpeed, reportedSpeed, desiredSpeed]` (the app derives on/off
from `filterSpeed`, and `on` restores `lastSpeed`), and `s` (a revision —
exposed as Display Rev).

**Diagnostics** (OPID `386` → reply `1386`): `v` (speed %), `p[3]`, `a`, `k`,
`W`, `Q`, `n`, `s[2]`. `s[0]`/`s[1]` are the radio and drive revisions
(formatted `minor.major.0`). The exact meaning of the remaining fields (`p[]`,
`W`, `Q`, `n`) isn't confirmed yet; `p[0]`/`a`/`k` are exposed as Power/Air
Temp/Drive Temp.

### Not wired up yet

The app also has builders for system on/off, equipment/heaters, priming,
schedules, alarms, time, Wi-Fi config and light control. Their opcodes are
numeric and can be reverse-engineered from captured BLE traffic.

### Other limitations

- The richer app states (`priming`, `stopped`, `freeze-protect`) still need the
  telemetry state field mapped — see the `TODO` in
  `esphome/components/omnix/omnix.cpp` (`process_telemetry_`).
- Discovery/scanning is paused while connected (BLE can't scan and connect at
  once); clear the MAC to scan.
- `invalid-key` covers no key stored, an unparseable key, and a well-formed but
  wrong key (the pump ACKs the auth write at the GATT level even with a wrong
  key, then never returns a decodable reply).
- The `dev`/`stat` advertisement bytes are shown but their meaning per device
  type isn't confirmed.
- `exclusive_ble: true` (opt-in, off by default) suspends Wi-Fi during each poll
  to give BLE the radio; see `esphome/README.md`.

## License

MIT — see [LICENSE](LICENSE). This project is unofficial and unaffiliated with
Hayward, and comes with no warranty; you use it at your own risk.
