#pragma once

#ifdef USE_ESP32

#include "esphome/core/component.h"
#include "esphome/core/preferences.h"
#include "esphome/components/esp32_ble_client/ble_client_base.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"

#include <array>
#include <deque>
#include <string>
#include <vector>

namespace esphome::omnix {

namespace espbt = esphome::esp32_ble_tracker;

// GATT service / characteristic of the OmniX "command pipe".
static const char *const OMNIX_CHAR_UUID = "66460130-8759-9bf8-b4db-7b04b9b026f1";
static const uint16_t OMNIX_SERVICE_UUID16 = 0xFCA5;

// CmdObj field ids / opcodes (see README).
static const char F_OPID = '\x03';
static const char F_SPEED = 'v';
static const char F_TID = '\x04';
static const char F_TELEM_ID = 'G';
static const uint16_t OPID_SET_FILTER_SPEED = 9;
static const uint16_t OPID_GET_TELEMETRY = 600;
static const uint16_t OPID_GET_DIAGNOSTIC = 386;

// The pump's speed is a percentage of its max motor speed. The app shows
// "50% / 1725 RPM", i.e. 100% == 3450 RPM, so RPM is derived (not reported).
static const int PUMP_MAX_RPM = 3450;

// Telemetry `V` array = [filterSpeed, lastSpeed, reportedSpeed, desiredSpeed]
static const size_t V_FILTER_SPEED = 0;
static const size_t V_LAST_SPEED = 1;

struct OmnixSavedConfig {
  uint8_t mac[6];
  uint8_t key[16];  // legacy field, kept for layout compatibility; unused now
  bool has_mac;
  bool valid;
} __attribute__((packed));

// The security key lives under its own NVS entry so that saving the MAC can
// never clobber it (the config's MAC fallback runs before setup() loads it).
struct OmnixKeyConfig {
  uint8_t key[16];
} __attribute__((packed));

class OmnixComponent : public esp32_ble_client::BLEClientBase {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_BLUETOOTH; }

  bool parse_device(const espbt::ESPBTDevice &device) override;
  bool gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;

  // --- configured by codegen ---
  void set_update_interval(uint32_t ms) { this->update_interval_ms_ = ms; }
  // Exclusive BLE mode: suspend Wi-Fi while talking to the pump (works around
  // ESP32-C3 single-radio Wi-Fi/BLE coexistence). The API link drops for the
  // duration of each window, so HA sees the device briefly unavailable.
  void set_exclusive_ble(bool v) { this->exclusive_ble_ = v; }
  void set_ble_window(uint32_t ms) { this->ble_window_ms_ = ms; }

  // --- HA-facing API (template lambdas) ---
  void set_mac_address(const std::string &mac);          // save + (re)target
  std::string get_mac_address() const { return this->mac_str_; }
  void set_security_key(const std::string &key);         // save key
  std::string get_key_masked() const { return this->key_valid_ ? "********" : ""; }

  bool is_connected() const { return this->state() == espbt::ClientState::ESTABLISHED; }
  // Returns NAN until we have actually read telemetry, so HA shows
  // "unknown" instead of a bogus -1%.
  float get_speed() const { return this->speed_percent_ < 0 ? NAN : (float) this->speed_percent_; }
  // "50%/1725 RPM", like the app's Diagnostics screen.
  std::string get_speed_display() const {
    if (this->speed_percent_ < 0)
      return "";
    char b[32];
    snprintf(b, sizeof(b), "%d%%/%d RPM", this->speed_percent_, this->speed_percent_ * PUMP_MAX_RPM / 100);
    return b;
  }
  // The commanded setpoint (what the number/control should show); tracks the
  // reported speed until the user sets one, then holds it until confirmed.
  float get_target_speed() const { return this->target_speed_ < 0 ? NAN : (float) this->target_speed_; }
  bool is_running() const { return this->running_; }
  std::string get_status() const { return this->status_; }
  std::string get_seen_devices() const;

  // --- diagnostics (OPID 386) ---
  float get_diag_power() const { return (this->diag_valid_ && !this->diag_p_.empty()) ? (float) this->diag_p_[0] : NAN; }
  float get_diag_air_temp() const { return this->diag_valid_ && this->diag_a_ >= 0 ? (float) this->diag_a_ : NAN; }
  float get_diag_drive_temp() const { return this->diag_valid_ && this->diag_k_ >= 0 ? (float) this->diag_k_ : NAN; }
  std::string get_diag_drive_rev() const { return format_rev_(this->diag_rev_.size() > 1 ? this->diag_rev_[1] : 0); }
  std::string get_diag_radio_rev() const { return format_rev_(this->diag_rev_.size() > 0 ? this->diag_rev_[0] : 0); }
  // Rev carried by the telemetry (600) message; the app labels this Display Rev.
  std::string get_display_rev() const { return format_rev_(this->telem_rev_); }

  void turn_on();
  void turn_off();
  void set_speed(int percent);

 protected:
  enum class Op : uint8_t { NONE, AUTH, REPLY };
  struct TxItem {
    std::vector<uint8_t> frame;
    bool read;
    Op op;
  };
  struct SeenDevice {
    uint64_t mac;
    uint8_t stat;
    uint8_t dev;
    int rssi;
    uint32_t seen_ms;
  };

  void load_config_();
  void load_key_();
  void save_config_();
  void save_key_();
  void set_target_mac_(uint64_t mac);
  void reset_session_();
  void start_auth_();
  void poll_status_();
  void poll_diagnostic_();
  void process_reply_(const std::string &ubjson);
  void process_diagnostic_(const std::string &ubjson);
  static std::string format_rev_(int32_t v);
  void pump_tx_();
  void on_write_();
  void on_read_(const uint8_t *value, uint16_t len);
  void finish_tx_();
  void update_ble_window_();
  void open_ble_window_();
  void close_ble_window_();

  bool send_plaintext_(const std::vector<uint8_t> &plaintext, Op op);
  void make_request_(uint32_t fc, uint32_t *out, size_t *out_len);
  std::vector<uint8_t> build_command_(const std::vector<std::pair<char, int>> &fields,
                                      uint32_t *tid_out);
  void handle_reply_(const uint8_t *value, uint16_t len);
  void process_telemetry_(const std::string &inner_ubjson);
  void record_seen_(const espbt::ESPBTDevice &device);

  uint32_t update_interval_ms_{30000};
  uint32_t last_poll_ms_{0};
  uint32_t last_seen_ms_{0};

  bool exclusive_ble_{false};
  bool ble_window_open_{false};
  bool fresh_telemetry_{false};      // telemetry received during the current window
  bool has_pending_speed_{false};    // a set_speed() deferred until we re-auth
  int pending_speed_{0};
  uint32_t ble_window_ms_{8000};     // max time Wi-Fi stays off per window
  uint32_t ble_window_start_{0};
  uint32_t next_window_ms_{0};

  bool has_target_{false};
  uint64_t target_mac_{0};
  std::string mac_str_;
  std::array<uint8_t, 16> key_{};
  bool key_valid_{false};

  bool target_seen_{false};
  std::vector<SeenDevice> seen_;

  uint16_t char_handle_{0};
  bool char_found_{false};
  std::array<uint8_t, 8> session_{};
  bool have_session_{false};
  uint32_t frame_counter_{1};
  bool auth_done_{false};
  uint32_t auth_ms_{0};             // when the current session authenticated
  bool session_replied_{false};     // a decodable reply arrived this session
  bool key_suspect_{false};         // no reply yet -> key looks wrong (sticky)

  std::deque<TxItem> tx_;
  bool busy_{false};
  bool read_pending_{false};   // a read is scheduled for tx_.front()
  bool awaiting_read_{false};  // a read request is in flight
  uint32_t read_due_ms_{0};
  uint8_t read_retries_{0};

  int speed_percent_{-1};
  int target_speed_{-1};
  bool target_pending_{false};  // user set a speed we haven't seen reported yet
  int last_speed_{-1};
  bool running_{false};
  bool got_telemetry_{false};  // parsed at least one telemetry reply
  bool is_pump_{false};        // that telemetry had pump speed fields

  // diagnostics (OPID 386 -> 1386): v, p[], a, W, k, Q, s[], n
  std::vector<int> diag_p_;
  std::vector<int32_t> diag_rev_;
  int diag_a_{-1};  // air temp
  int diag_k_{-1};  // drive temp
  int diag_v_{-1};  // speed %
  int diag_w_{0}, diag_q_{0}, diag_n_{0};
  bool diag_valid_{false};
  int32_t telem_rev_{0};  // telemetry 's' field (Display rev)
  std::string diag_raw_;
  std::string status_{"unknown"};
};

}  // namespace esphome::omnix

#endif  // USE_ESP32
