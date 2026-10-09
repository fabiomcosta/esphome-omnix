import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import esp32_ble, esp32_ble_client, esp32_ble_tracker
from esphome.components.esp32_ble import BTLoggers
from esphome.const import CONF_ID, CONF_MAC_ADDRESS
from esphome.types import ConfigType

CODEOWNERS = ["@fabiomcosta"]
DEPENDENCIES = ["esp32_ble_tracker"]
AUTO_LOAD = ["esp32_ble_client"]

CONF_SECURITY_KEY = "security_key"
CONF_UPDATE_INTERVAL = "update_interval"
CONF_EXCLUSIVE_BLE = "exclusive_ble"
CONF_BLE_WINDOW = "ble_window"

omnix_ns = cg.esphome_ns.namespace("omnix")
OmnixComponent = omnix_ns.class_(
    "OmnixComponent", esp32_ble_client.BLEClientBase, cg.Component
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(OmnixComponent),
            cv.Optional(CONF_MAC_ADDRESS): cv.mac_address,
            cv.Optional(CONF_SECURITY_KEY): cv.string,
            cv.Optional(
                CONF_UPDATE_INTERVAL, default="30s"
            ): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_EXCLUSIVE_BLE, default=False): cv.boolean,
            cv.Optional(
                CONF_BLE_WINDOW, default="8s"
            ): cv.positive_time_period_milliseconds,
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
    .extend(esp32_ble_tracker.ESP_BLE_DEVICE_SCHEMA),
    esp32_ble.consume_connection_slots(1, "omnix"),
)


async def to_code(config: ConfigType) -> None:
    esp32_ble.register_bt_logger(BTLoggers.GATT, BTLoggers.SMP)
    cg.add_define("USE_ESP32_BLE_UUID")

    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await esp32_ble_tracker.register_client(var, config)

    if CONF_MAC_ADDRESS in config:
        cg.add(var.set_mac_address(str(config[CONF_MAC_ADDRESS])))
    if CONF_SECURITY_KEY in config:
        cg.add(var.set_security_key(config[CONF_SECURITY_KEY]))
    cg.add(var.set_update_interval(config[CONF_UPDATE_INTERVAL]))
    cg.add(var.set_exclusive_ble(config[CONF_EXCLUSIVE_BLE]))
    cg.add(var.set_ble_window(config[CONF_BLE_WINDOW]))
