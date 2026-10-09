#include "omnix.h"

#ifdef USE_ESP32

#include "esphome/core/application.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"

#ifdef USE_WIFI
#include "esphome/components/wifi/wifi_component.h"
#endif

#include <esp_gattc_api.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>

#include <cstring>

namespace esphome::omnix {

static const char *const TAG = "omnix";

// 4-byte frame counter + 16-byte GCM tag appended to the ciphertext.
static const size_t FRAME_OVERHEAD = 20;

// If we authenticate but never get a decodable reply within this window, the
// key is wrong (with a correct key the first poll replies in ~1s).
static const uint32_t AUTH_REPLY_TIMEOUT_MS = 7000;

// ---------------------------------------------------------------------------
// UBJSON (the exact @shelacek/ubjson flavour the OmniX app uses)
// ---------------------------------------------------------------------------

static void ubj_len(std::vector<uint8_t> &out, size_t n) {
  if (n <= 127) {
    out.push_back('i');
    out.push_back((uint8_t) n);
  } else if (n <= 255) {
    out.push_back('U');
    out.push_back((uint8_t) n);
  } else {
    out.push_back('I');
    out.push_back((uint8_t) (n >> 8));
    out.push_back((uint8_t) n);
  }
}

static void ubj_key(std::vector<uint8_t> &out, char k) {
  ubj_len(out, 1);
  out.push_back((uint8_t) k);
}

static void ubj_int(std::vector<uint8_t> &out, int v) {
  if (v >= -128 && v <= 127) {
    out.push_back('i');
    out.push_back((uint8_t) v);
  } else if (v >= 0 && v <= 255) {
    out.push_back('U');
    out.push_back((uint8_t) v);
  } else {
    out.push_back('I');
    out.push_back((uint8_t) (v >> 8));
    out.push_back((uint8_t) v);
  }
}

struct UbjVal {
  enum Type { NIL, BOOL, INT, STR, ARR, OBJ } type{NIL};
  int64_t i{0};
  bool b{false};
  std::string s;
  std::vector<UbjVal> arr;
  std::vector<std::pair<std::string, UbjVal>> obj;
};

static bool ubj_read_len(const uint8_t *b, size_t len, size_t &pos, size_t &out) {
  if (pos >= len)
    return false;
  char t = (char) b[pos++];
  if (t == 'i' || t == 'U') {
    if (pos >= len)
      return false;
    out = b[pos++];
  } else if (t == 'I') {
    if (pos + 2 > len)
      return false;
    out = ((size_t) b[pos] << 8) | b[pos + 1];
    pos += 2;
  } else {
    return false;
  }
  return true;
}

static bool ubj_parse(const uint8_t *b, size_t len, size_t &pos, UbjVal &out);

static bool ubj_parse_val(const uint8_t *b, size_t len, size_t &pos, char t, UbjVal &out) {
  switch (t) {
    case 'Z':
      out.type = UbjVal::NIL;
      return true;
    case 'T':
      out.type = UbjVal::BOOL;
      out.b = true;
      return true;
    case 'F':
      out.type = UbjVal::BOOL;
      out.b = false;
      return true;
    case 'i':
    case 'U': {
      if (pos >= len)
        return false;
      out.type = UbjVal::INT;
      out.i = (t == 'i') ? (int8_t) b[pos] : (uint8_t) b[pos];
      pos++;
      return true;
    }
    case 'I': {
      if (pos + 2 > len)
        return false;
      out.type = UbjVal::INT;
      out.i = (int16_t) (((uint16_t) b[pos] << 8) | b[pos + 1]);
      pos += 2;
      return true;
    }
    case 'l': {
      if (pos + 4 > len)
        return false;
      out.type = UbjVal::INT;
      out.i = (int32_t) (((uint32_t) b[pos] << 24) | ((uint32_t) b[pos + 1] << 16) |
                         ((uint32_t) b[pos + 2] << 8) | b[pos + 3]);
      pos += 4;
      return true;
    }
    case 'S':
    case 'C':
    case 'H': {
      size_t n = 0;
      if (!ubj_read_len(b, len, pos, n) || pos + n > len)
        return false;
      out.type = UbjVal::STR;
      out.s.assign((const char *) b + pos, n);
      pos += n;
      return true;
    }
    default:
      return false;
  }
}

static bool ubj_parse(const uint8_t *b, size_t len, size_t &pos, UbjVal &out) {
  if (pos >= len)
    return false;
  char t = (char) b[pos++];
  if (t == '{') {
    out.type = UbjVal::OBJ;
    while (pos < len && b[pos] != '}') {
      size_t klen = 0;
      if (!ubj_read_len(b, len, pos, klen) || pos + klen > len)
        return false;
      std::string key((const char *) b + pos, klen);
      pos += klen;
      UbjVal v;
      if (!ubj_parse(b, len, pos, v))
        return false;
      out.obj.emplace_back(std::move(key), std::move(v));
    }
    if (pos >= len)
      return false;
    pos++;  // '}'
    return true;
  }
  if (t == '[') {
    out.type = UbjVal::ARR;
    char elem_type = 0;
    size_t count = SIZE_MAX;
    if (pos < len && b[pos] == '$') {
      pos++;
      if (pos >= len)
        return false;
      elem_type = (char) b[pos++];
    }
    if (pos < len && b[pos] == '#') {
      pos++;
      if (!ubj_read_len(b, len, pos, count))
        return false;
    }
    if (count != SIZE_MAX) {
      for (size_t n = 0; n < count; n++) {
        UbjVal v;
        if (!ubj_parse_val(b, len, pos, elem_type, v))
          return false;
        out.arr.push_back(std::move(v));
      }
      return true;
    }
    while (pos < len && b[pos] != ']') {
      UbjVal v;
      if (!ubj_parse(b, len, pos, v))
        return false;
      out.arr.push_back(std::move(v));
    }
    if (pos >= len)
      return false;
    pos++;  // ']'
    return true;
  }
  return ubj_parse_val(b, len, pos, t, out);
}

static const UbjVal *ubj_get(const UbjVal &obj, char key) {
  if (obj.type != UbjVal::OBJ)
    return nullptr;
  for (const auto &kv : obj.obj)
    if (kv.first.size() == 1 && kv.first[0] == key)
      return &kv.second;
  return nullptr;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static uint64_t pack_mac(const uint8_t *m) {
  return ((uint64_t) m[0] << 40) | ((uint64_t) m[1] << 32) | ((uint64_t) m[2] << 24) |
         ((uint64_t) m[3] << 16) | ((uint64_t) m[4] << 8) | m[5];
}

static bool parse_hex(const std::string &in, uint8_t *out, size_t out_len) {
  size_t n = 0;
  int hi = -1;
  for (char c : in) {
    // Accept a plain hex string or a UUID-style string: ignore separators and
    // surrounding braces, e.g. "00112233-4455-6677-8899-aabbccddeeff".
    if (c == ':' || c == '-' || c == ' ' || c == '\t' || c == '{' || c == '}')
      continue;
    int v;
    if (c >= '0' && c <= '9')
      v = c - '0';
    else if (c >= 'a' && c <= 'f')
      v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      v = c - 'A' + 10;
    else
      return false;
    if (hi < 0) {
      hi = v;
    } else {
      if (n >= out_len)
        return false;
      out[n++] = (uint8_t) ((hi << 4) | v);
      hi = -1;
    }
  }
  return hi < 0 && n == out_len;
}

// ---------------------------------------------------------------------------
// component
// ---------------------------------------------------------------------------

void OmnixComponent::setup() {
  BLEClientBase::setup();
  this->set_auto_connect(true);
  this->load_config_();
  if (this->exclusive_ble_) {
    this->next_window_ms_ = millis() + 8000;  // let Wi-Fi/API come up first
    ESP_LOGI(TAG, "Exclusive BLE mode: Wi-Fi is suspended during each poll window");
  }
}

void OmnixComponent::dump_config() {
  BLEClientBase::dump_config();
  ESP_LOGCONFIG(TAG, "OmniX Pump:");
  ESP_LOGCONFIG(TAG, "  Target MAC: %s", this->has_target_ ? this->mac_str_.c_str() : "(not set)");
  ESP_LOGCONFIG(TAG, "  Security key: %s", this->key_valid_ ? "set" : "MISSING");
  ESP_LOGCONFIG(TAG, "  Update interval: %lu ms", (unsigned long) this->update_interval_ms_);
  if (this->exclusive_ble_)
    ESP_LOGCONFIG(TAG, "  Exclusive BLE: yes (window %lu ms)", (unsigned long) this->ble_window_ms_);
}

void OmnixComponent::load_key_() {
  auto pref = global_preferences->make_preference<OmnixKeyConfig>(fnv1_hash("omnix_key"));
  OmnixKeyConfig cfg{};
  if (!pref.load(&cfg))
    return;
  bool zero = true;
  for (uint8_t b : cfg.key) {
    if (b != 0) {
      zero = false;
      break;
    }
  }
  if (zero)
    return;
  memcpy(this->key_.data(), cfg.key, 16);
  this->key_valid_ = true;
}

void OmnixComponent::save_key_() {
  OmnixKeyConfig cfg{};
  memcpy(cfg.key, this->key_.data(), 16);
  auto pref = global_preferences->make_preference<OmnixKeyConfig>(fnv1_hash("omnix_key"));
  pref.save(&cfg);
  global_preferences->sync();
}

void OmnixComponent::load_config_() {
  this->load_key_();

  auto pref = global_preferences->make_preference<OmnixSavedConfig>(fnv1_hash("omnix_cfg"));
  OmnixSavedConfig cfg{};
  if (!pref.load(&cfg) || !cfg.valid)
    return;
  if (cfg.has_mac) {
    char buf[MAC_ADDRESS_PRETTY_BUFFER_SIZE];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", cfg.mac[0], cfg.mac[1], cfg.mac[2],
             cfg.mac[3], cfg.mac[4], cfg.mac[5]);
    this->mac_str_ = buf;
    this->set_target_mac_(pack_mac(cfg.mac));
    ESP_LOGI(TAG, "Restored target %s", buf);
  }
}

void OmnixComponent::save_config_() {
  if (!this->has_target_ && !this->key_valid_)
    return;
  OmnixSavedConfig cfg{};
  cfg.valid = true;
  cfg.has_mac = this->has_target_;
  if (this->has_target_) {
    cfg.mac[0] = (this->target_mac_ >> 40) & 0xFF;
    cfg.mac[1] = (this->target_mac_ >> 32) & 0xFF;
    cfg.mac[2] = (this->target_mac_ >> 24) & 0xFF;
    cfg.mac[3] = (this->target_mac_ >> 16) & 0xFF;
    cfg.mac[4] = (this->target_mac_ >> 8) & 0xFF;
    cfg.mac[5] = this->target_mac_ & 0xFF;
  }
  auto pref = global_preferences->make_preference<OmnixSavedConfig>(fnv1_hash("omnix_cfg"));
  pref.save(&cfg);
  // save() only buffers the value in RAM; sync() is what commits it to NVS.
  // Without this the key/MAC can be lost across a reset or OTA.
  global_preferences->sync();
}

void OmnixComponent::set_target_mac_(uint64_t mac) {
  this->target_mac_ = mac;
  this->has_target_ = true;
  this->target_seen_ = false;
  this->got_telemetry_ = false;
  this->is_pump_ = false;
  this->speed_percent_ = -1;
  this->target_speed_ = -1;
  this->target_pending_ = false;
  this->last_speed_ = -1;
  this->running_ = false;
  this->set_address(mac);
  if (this->is_connected())
    this->disconnect();
}

void OmnixComponent::set_mac_address(const std::string &mac) {
  if (mac.empty()) {
    this->has_target_ = false;
    this->target_seen_ = false;
    this->got_telemetry_ = false;
    this->is_pump_ = false;
    this->speed_percent_ = -1;
    this->target_speed_ = -1;
    this->target_pending_ = false;
    this->last_speed_ = -1;
    this->running_ = false;
    this->mac_str_.clear();
    this->set_address(0);
    if (this->is_connected())
      this->disconnect();
    this->save_config_();
    ESP_LOGI(TAG, "Target cleared; scanning for OmniX devices");
    return;
  }
  uint8_t bytes[6];
  if (!parse_hex(mac, bytes, 6)) {
    ESP_LOGW(TAG, "Invalid MAC '%s'", mac.c_str());
    return;
  }
  char buf[MAC_ADDRESS_PRETTY_BUFFER_SIZE];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", bytes[0], bytes[1], bytes[2], bytes[3],
           bytes[4], bytes[5]);
  this->mac_str_ = buf;
  this->set_target_mac_(pack_mac(bytes));
  this->save_config_();
  ESP_LOGI(TAG, "Target set to %s", buf);
}

void OmnixComponent::set_security_key(const std::string &key) {
  if (key.empty())
    return;
  uint8_t bytes[16];
  if (!parse_hex(key, bytes, 16)) {
    ESP_LOGW(TAG, "Invalid security key '%s' (expected 16 bytes as hex, with or without dashes)",
             key.c_str());
    return;
  }
  memcpy(this->key_.data(), bytes, 16);
  this->key_valid_ = true;
  // Re-evaluate from scratch with the new key.
  this->key_suspect_ = false;
  this->got_telemetry_ = false;
  this->is_pump_ = false;
  this->save_key_();
  ESP_LOGI(TAG, "Security key saved");
  if (this->is_connected() && this->char_found_) {
    this->reset_session_();
    this->char_found_ = true;
    this->start_auth_();
  }
}

// --- discovery -------------------------------------------------------------

void OmnixComponent::record_seen_(const espbt::ESPBTDevice &device) {
  const uint8_t *mac = nullptr;
  uint8_t stat = 0, dev = 0;
  for (const auto &md : device.get_manufacturer_datas()) {
    if (md.uuid.uuid16() == 0x0CEA && md.data.size() >= 8) {
      stat = md.data[0];
      dev = md.data[1];
      mac = md.data.data() + 2;
      break;
    }
  }
  bool is_omni = mac != nullptr;
  if (!is_omni) {
    for (const auto &uuid : device.get_service_uuids()) {
      if (uuid.uuid16() == OMNIX_SERVICE_UUID16) {
        is_omni = true;
        break;
      }
    }
  }
  if (!is_omni)
    return;

  uint64_t addr = mac ? pack_mac(mac) : device.address_uint64();
  uint32_t now = millis();
  for (auto &s : this->seen_) {
    if (s.mac == addr) {
      s.rssi = device.get_rssi();
      s.seen_ms = now;
      if (mac) {
        s.stat = stat;
        s.dev = dev;
      }
      this->last_seen_ms_ = now;
      return;
    }
  }
  if (this->seen_.size() >= 8)
    this->seen_.erase(this->seen_.begin());
  this->seen_.push_back({addr, stat, dev, device.get_rssi(), now});
  this->last_seen_ms_ = now;
}

bool OmnixComponent::parse_device(const espbt::ESPBTDevice &device) {
  this->record_seen_(device);
  if (!this->has_target_)
    return false;

  // Match on the MAC the user selected. Prefer the advertised (connectable)
  // address, but recognise the device by either the manufacturer MAC or the
  // BLE address so public/random addresses both work.
  bool match = device.address_uint64() == this->target_mac_;
  if (!match) {
    for (const auto &md : device.get_manufacturer_datas()) {
      if (md.uuid.uuid16() == 0x0CEA && md.data.size() >= 8) {
        uint8_t m[6] = {md.data[2], md.data[3], md.data[4], md.data[5], md.data[6], md.data[7]};
        if (pack_mac(m) == this->target_mac_) {
          match = true;
          break;
        }
      }
    }
  }
  if (!match)
    return false;

  this->target_seen_ = true;
  this->set_address(device.address_uint64());  // connect to the advertised address
  return BLEClientBase::parse_device(device);
}

std::string OmnixComponent::get_seen_devices() const {
  std::string out;
  uint32_t now = millis();
  for (const auto &s : this->seen_) {
    if (now - s.seen_ms > 60000)
      continue;
    char buf[64];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X dev=%u stat=%u rssi=%d",
             (unsigned) ((s.mac >> 40) & 0xFF), (unsigned) ((s.mac >> 32) & 0xFF),
             (unsigned) ((s.mac >> 24) & 0xFF), (unsigned) ((s.mac >> 16) & 0xFF),
             (unsigned) ((s.mac >> 8) & 0xFF), (unsigned) (s.mac & 0xFF), s.dev, s.stat, s.rssi);
    if (!out.empty())
      out += " | ";
    out += buf;
  }
  return out;
}

// --- protocol --------------------------------------------------------------

void OmnixComponent::reset_session_() {
  this->tx_.clear();
  this->busy_ = false;
  this->read_pending_ = false;
  this->awaiting_read_ = false;
  this->read_retries_ = 0;
  this->auth_done_ = false;
  this->have_session_ = false;
  this->char_found_ = false;
  this->frame_counter_ = 1;
}

void OmnixComponent::start_auth_() {
  this->auth_done_ = false;
  this->have_session_ = false;
  this->frame_counter_ = 1;
  TxItem item;
  item.frame = {0x06};
  item.read = true;
  item.op = Op::AUTH;
  this->tx_.push_back(std::move(item));
  this->pump_tx_();
}

void OmnixComponent::finish_tx_() {
  if (!this->tx_.empty())
    this->tx_.pop_front();
  this->busy_ = false;
  if (this->have_session_ && !this->auth_done_ && this->tx_.empty()) {
    this->auth_done_ = true;
    this->auth_ms_ = millis();
    this->session_replied_ = false;
    this->last_poll_ms_ = 0;
    ESP_LOGI(TAG, "Authenticated (session %02x%02x%02x%02x...)", this->session_[0],
             this->session_[1], this->session_[2], this->session_[3]);
    if (this->has_pending_speed_) {
      int p = this->pending_speed_;
      this->has_pending_speed_ = false;
      this->set_speed(p);
    }
    this->poll_status_();
    return;
  }
  this->pump_tx_();
}

void OmnixComponent::pump_tx_() {
  if (this->busy_ || this->tx_.empty() || !this->is_connected() || !this->char_found_)
    return;
  this->read_retries_ = 0;
  auto &item = this->tx_.front();
  esp_err_t err = esp_ble_gattc_write_char(this->get_gattc_if(), this->get_conn_id(),
                                           this->char_handle_, item.frame.size(), item.frame.data(),
                                           ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Write failed: %s", esp_err_to_name(err));
    this->finish_tx_();
    return;
  }
  this->busy_ = true;
}

void OmnixComponent::on_write_() {
  if (this->tx_.empty()) {
    this->busy_ = false;
    return;
  }
  auto &item = this->tx_.front();
  ESP_LOGD(TAG, "Write done (op=%d); %s read", (int) item.op, item.read ? "scheduling" : "no");
  if (item.read) {
    // Give the pump a moment to process the write and update the
    // characteristic before reading it back.
    this->read_pending_ = true;
    this->read_due_ms_ = millis() + 80;
    return;
  }
  this->finish_tx_();
}

void OmnixComponent::on_read_(const uint8_t *value, uint16_t len) {
  this->awaiting_read_ = false;
  Op op = this->tx_.empty() ? Op::NONE : this->tx_.front().op;
  ESP_LOGD(TAG, "Read event (op=%d, len=%u)", (int) op, (unsigned) len);
  // The pump needs a moment to update the characteristic after a write; retry
  // the read until a complete frame arrives (rather than a stale/partial one).
  if (op == Op::REPLY && len < FRAME_OVERHEAD && this->read_retries_ < 5) {
    this->read_retries_++;
    this->read_pending_ = true;
    this->read_due_ms_ = millis() + 60;
    return;
  }
  this->read_retries_ = 0;
  if (op == Op::AUTH && len == 16) {
    // challenge -> AES-128-ECB(challenge, key)
    uint8_t resp[16];
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, this->key_.data(), 128);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, value, resp);
    mbedtls_aes_free(&aes);
    memcpy(this->session_.data(), value, 8);
    this->have_session_ = true;
    TxItem item;
    item.frame.push_back(0x06);
    item.frame.insert(item.frame.end(), resp, resp + 16);
    item.read = false;
    item.op = Op::NONE;
    this->tx_.push_back(std::move(item));
  } else if (op == Op::REPLY) {
    this->handle_reply_(value, len);
  }
  this->finish_tx_();
}

bool OmnixComponent::send_plaintext_(const std::vector<uint8_t> &plaintext, Op op) {
  if (!this->have_session_ || !this->key_valid_)
    return false;
  uint32_t fc = this->frame_counter_++;
  uint8_t iv[12] = {0};
  iv[0] = (fc >> 24) & 0xFF;
  iv[1] = (fc >> 16) & 0xFF;
  iv[2] = (fc >> 8) & 0xFF;
  iv[3] = fc & 0xFF;
  memcpy(iv + 4, this->session_.data(), 8);

  std::vector<uint8_t> ct(plaintext.size());
  uint8_t tag[16];
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, this->key_.data(), 128);
  int rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), iv, sizeof(iv),
                                     nullptr, 0, plaintext.data(), ct.data(), 16, tag);
  mbedtls_gcm_free(&gcm);
  if (rc != 0) {
    ESP_LOGW(TAG, "GCM encrypt failed: %d", rc);
    return false;
  }

  std::vector<uint8_t> frame;
  frame.reserve(1 + ct.size() + 4 + 16 + 4);
  frame.push_back(0x07);
  frame.insert(frame.end(), ct.begin(), ct.end());
  frame.push_back(iv[0]);
  frame.push_back(iv[1]);
  frame.push_back(iv[2]);
  frame.push_back(iv[3]);
  frame.insert(frame.end(), tag, tag + 16);

  TxItem item;
  item.frame = std::move(frame);
  item.read = true;
  item.op = op;
  this->tx_.push_back(std::move(item));
  this->pump_tx_();
  return true;
}

std::vector<uint8_t> OmnixComponent::build_command_(const std::vector<std::pair<char, int>> &fields,
                                                    uint32_t *tid_out) {
  std::vector<uint8_t> out;
  out.push_back(0x02);
  for (int i = 5; i >= 0; i--)
    out.push_back((this->target_mac_ >> (i * 8)) & 0xFF);
  out.push_back('{');
  for (auto &f : fields) {
    ubj_key(out, f.first);
    ubj_int(out, f.second);
  }
  out.push_back('}');
  (void) tid_out;
  return out;
}

void OmnixComponent::poll_status_() {
  if (!this->auth_done_)
    return;
  ESP_LOGD(TAG, "Polling telemetry");
  uint32_t tid = 0;
  auto pt = this->build_command_({{F_OPID, OPID_GET_TELEMETRY}, {F_TELEM_ID, 0}}, &tid);
  if (this->send_plaintext_(pt, Op::REPLY))
    this->last_poll_ms_ = millis();
  else
    ESP_LOGW(TAG, "Failed to send telemetry request");
  this->poll_diagnostic_();
}

void OmnixComponent::poll_diagnostic_() {
  if (!this->auth_done_)
    return;
  ESP_LOGD(TAG, "Polling diagnostics");
  uint32_t tid = random_uint32() & 0x7FFF;
  auto pt = this->build_command_({{F_OPID, OPID_GET_DIAGNOSTIC}, {F_TID, (int) tid}}, &tid);
  this->send_plaintext_(pt, Op::REPLY);
}

void OmnixComponent::process_telemetry_(const std::string &ubjson) {
  size_t pos = 0;
  UbjVal outer;
  if (!ubj_parse((const uint8_t *) ubjson.data(), ubjson.size(), pos, outer))
    return;
  const UbjVal *g = ubj_get(outer, 'g');
  if (g == nullptr)
    return;

  std::vector<uint8_t> inner_bytes;
  if (g->type == UbjVal::ARR) {
    inner_bytes.reserve(g->arr.size());
    for (const auto &v : g->arr)
      if (v.type == UbjVal::INT)
        inner_bytes.push_back((uint8_t) v.i);
  } else if (g->type == UbjVal::STR) {
    inner_bytes.assign(g->s.begin(), g->s.end());
  } else {
    return;
  }

  size_t ipos = 0;
  UbjVal inner;
  if (!ubj_parse(inner_bytes.data(), inner_bytes.size(), ipos, inner))
    return;
  this->got_telemetry_ = true;  // we did get a telemetry payload
  this->fresh_telemetry_ = true;
  if (const UbjVal *rs = ubj_get(inner, 's'); rs != nullptr && rs->type == UbjVal::INT)
    this->telem_rev_ = (int32_t) rs->i;

  const UbjVal *v = ubj_get(inner, 'V');
  if (v == nullptr || v->type != UbjVal::ARR)
    return;  // answer is a valid telemetry reply but has no pump speed array
  this->is_pump_ = true;
  if (v->arr.size() > V_FILTER_SPEED && v->arr[V_FILTER_SPEED].type == UbjVal::INT)
    this->speed_percent_ = (int) v->arr[V_FILTER_SPEED].i;
  if (v->arr.size() > V_LAST_SPEED && v->arr[V_LAST_SPEED].type == UbjVal::INT)
    this->last_speed_ = (int) v->arr[V_LAST_SPEED].i;
  ESP_LOGI(TAG, "Telemetry: speed=%d last=%d rev=%08x", this->speed_percent_, this->last_speed_,
           (unsigned) this->telem_rev_);
  const UbjVal *e = ubj_get(inner, 'e');
  (void) e;
  // TODO: map the telemetry state field (IOT_PARAMS_STATE / WHYISON) to the
  // app's richer PumpStatus (priming / stopped / freeze-protect). We currently
  // only derive running vs paused from the reported speed.
  // Reconcile the displayed setpoint: hold the target while waiting for the
  // pump to report it, otherwise track the reported speed.
  if (this->target_pending_) {
    if (this->speed_percent_ == this->target_speed_)
      this->target_pending_ = false;
  } else {
    this->target_speed_ = this->speed_percent_;
  }
  this->running_ = this->speed_percent_ > 0;
}

void OmnixComponent::handle_reply_(const uint8_t *value, uint16_t len) {
  if (len < FRAME_OVERHEAD)
    return;
  uint32_t fc = ((uint32_t) value[len - 20] << 24) | ((uint32_t) value[len - 19] << 16) |
                ((uint32_t) value[len - 18] << 8) | value[len - 17];
  const uint8_t *ct = value;
  size_t ct_len = len - 20;
  const uint8_t *tag = value + len - 16;

  uint8_t iv[12] = {0};
  iv[0] = (fc >> 24) & 0xFF;
  iv[1] = (fc >> 16) & 0xFF;
  iv[2] = (fc >> 8) & 0xFF;
  iv[3] = fc & 0xFF;
  for (int i = 0; i < 8; i++)
    iv[4 + i] = this->session_[7 - i];  // device reverses the session id

  ESP_LOGD(TAG, "Reply %u bytes (fc=%lu)", (unsigned) len, (unsigned long) fc);
  std::vector<uint8_t> pt(ct_len);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, this->key_.data(), 128);
  int rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, iv, sizeof(iv), nullptr, 0, tag, 16, ct, pt.data());
  mbedtls_gcm_free(&gcm);
  if (rc != 0) {
    ESP_LOGD(TAG, "Reply decrypt failed: %d", rc);
    return;
  }
  this->session_replied_ = true;
  this->key_suspect_ = false;
  if (pt.size() < 8)
    return;
  std::string ubjson((const char *) pt.data() + 7, pt.size() - 7);
  this->process_reply_(ubjson);
}

void OmnixComponent::process_reply_(const std::string &ubjson) {
  size_t pos = 0;
  UbjVal o;
  if (!ubj_parse((const uint8_t *) ubjson.data(), ubjson.size(), pos, o))
    return;
  const UbjVal *op = ubj_get(o, '\x03');
  int opid = (op != nullptr && op->type == UbjVal::INT) ? (int) op->i : -1;
  if (opid == OPID_GET_TELEMETRY + 1000)
    this->process_telemetry_(ubjson);
  else if (opid == OPID_GET_DIAGNOSTIC + 1000)
    this->process_diagnostic_(ubjson);
}

std::string OmnixComponent::format_rev_(int32_t v) {
  // Rev lives in the high 16 bits, encoded as (minor << 8) | major; the low
  // 16 bits carry a varying status we ignore.
  char b[24];
  snprintf(b, sizeof(b), "%u.%u.0", (unsigned) ((v >> 16) & 0xFF), (unsigned) ((v >> 24) & 0xFF));
  return b;
}

void OmnixComponent::process_diagnostic_(const std::string &ubjson) {
  size_t pos = 0;
  UbjVal o;
  if (!ubj_parse((const uint8_t *) ubjson.data(), ubjson.size(), pos, o))
    return;
  auto geti = [&](char k, int dflt) -> int {
    const UbjVal *v = ubj_get(o, k);
    return (v != nullptr && v->type == UbjVal::INT) ? (int) v->i : dflt;
  };
  this->diag_v_ = geti('v', -1);
  this->diag_a_ = geti('a', -1);
  this->diag_k_ = geti('k', -1);
  this->diag_w_ = geti('W', 0);
  this->diag_q_ = geti('Q', 0);
  this->diag_n_ = geti('n', 0);
  this->diag_p_.clear();
  if (const UbjVal *p = ubj_get(o, 'p'); p != nullptr && p->type == UbjVal::ARR)
    for (const auto &e : p->arr)
      if (e.type == UbjVal::INT)
        this->diag_p_.push_back((int) e.i);
  this->diag_rev_.clear();
  if (const UbjVal *s = ubj_get(o, 's'); s != nullptr && s->type == UbjVal::ARR)
    for (const auto &e : s->arr)
      if (e.type == UbjVal::INT)
        this->diag_rev_.push_back((int32_t) e.i);
  this->diag_valid_ = true;

  std::string p, s;
  for (size_t i = 0; i < this->diag_p_.size(); i++) {
    if (i)
      p += ",";
    p += std::to_string(this->diag_p_[i]);
  }
  char hex[16];
  for (size_t i = 0; i < this->diag_rev_.size(); i++) {
    if (i)
      s += ",";
    snprintf(hex, sizeof(hex), "%08x", (unsigned) this->diag_rev_[i]);
    s += hex;
  }
  this->diag_raw_ = "v=" + std::to_string(this->diag_v_) + " p=[" + p + "] a=" + std::to_string(this->diag_a_) +
                    " k=" + std::to_string(this->diag_k_) + " W=" + std::to_string(this->diag_w_) +
                    " Q=" + std::to_string(this->diag_q_) + " n=" + std::to_string(this->diag_n_) + " s=[" + s + "]";
  ESP_LOGI(TAG, "Diag: %s", this->diag_raw_.c_str());
}

void OmnixComponent::set_speed(int percent) {
  if (percent < 0)
    percent = 0;
  if (percent > 100)
    percent = 100;
  // Remember the setpoint immediately so the control shows the requested value
  // while we wait for the pump to actually report it.
  this->target_speed_ = percent;
  this->target_pending_ = true;
  if (!this->auth_done_ || !this->is_connected()) {
    // The BLE link drops between polls, so a command issued while it is down
    // must be remembered and sent once we re-authenticate rather than being
    // dropped (which made the Power switch look like it did nothing).
    this->pending_speed_ = percent;
    this->has_pending_speed_ = true;
    this->running_ = percent > 0;
    this->next_window_ms_ = 0;
    ESP_LOGI(TAG, "Speed %d%% queued until the link is back", percent);
    return;
  }
  uint32_t tid = random_uint32() & 0x7FFF;
  auto pt = this->build_command_(
      {{F_OPID, OPID_SET_FILTER_SPEED}, {F_SPEED, percent}, {F_TID, (int) tid}}, &tid);
  ESP_LOGI(TAG, "Set speed %d%%", percent);
  if (this->send_plaintext_(pt, Op::REPLY)) {
    this->running_ = percent > 0;
  }
}

void OmnixComponent::turn_on() {
  int target = this->last_speed_ > 0 ? this->last_speed_
               : this->speed_percent_ > 0 ? this->speed_percent_
                                          : 50;
  this->set_speed(target);
}

void OmnixComponent::turn_off() { this->set_speed(0); }

void OmnixComponent::loop() {
  BLEClientBase::loop();
  this->update_ble_window_();

  // expire discovery entries
  if (this->has_target_) {
    bool seen = false;
    uint32_t now = millis();
    for (auto &s : this->seen_)
      if (s.mac == this->target_mac_ && now - s.seen_ms <= 60000)
        seen = true;
    this->target_seen_ = seen;
  }

  if (this->read_pending_ && !this->awaiting_read_ && millis() >= this->read_due_ms_ &&
      this->is_connected() && this->char_found_) {
    this->read_pending_ = false;
    esp_err_t err = esp_ble_gattc_read_char(this->get_gattc_if(), this->get_conn_id(),
                                            this->char_handle_, ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "Read request failed: %s", esp_err_to_name(err));
      this->finish_tx_();
    } else {
      this->awaiting_read_ = true;
    }
  }

  if (!this->is_connected()) {
    // No link: keep the pump's last known status rather than reporting the
    // ESP32's connection state here (that is not a pump status).
    return;
  }
  if (!this->auth_done_) {
    this->status_ = "connecting";
    return;
  }
  // Auth is only ACKed at the GATT level, so a wrong key still "succeeds" but
  // the pump never sends a decodable reply. Once we have waited long enough
  // that a good key would certainly have answered, mark the key suspect -- and
  // keep it that way across reconnects until a reply actually arrives.
  if (!this->session_replied_ && !this->key_suspect_ &&
      millis() - this->auth_ms_ > AUTH_REPLY_TIMEOUT_MS) {
    this->key_suspect_ = true;
    ESP_LOGW(TAG, "No reply from the pump; the security key looks wrong");
  }
  if (this->key_suspect_) {
    this->status_ = "invalid-key";
    return;
  }
  if (!this->got_telemetry_) {
    this->status_ = "waiting";
    return;
  }
  if (!this->is_pump_) {
    this->status_ = "not-a-pump";
    return;
  }
  this->status_ = this->running_ ? "running" : "paused";

  if (!this->busy_ && this->tx_.empty() &&
      (this->last_poll_ms_ == 0 || millis() - this->last_poll_ms_ >= this->update_interval_ms_)) {
    this->poll_status_();
  }
}

void OmnixComponent::update_ble_window_() {
  if (!this->exclusive_ble_)
    return;

  uint32_t now = millis();
  if (!this->ble_window_open_) {
    if (now >= this->next_window_ms_)
      this->open_ble_window_();
    return;
  }
  // End the window as soon as telemetry arrives, but never exceed the timeout
  // so Wi-Fi is always restored (safety).
  if (this->fresh_telemetry_ || now - this->ble_window_start_ >= this->ble_window_ms_)
    this->close_ble_window_();
}

void OmnixComponent::open_ble_window_() {
  this->ble_window_open_ = true;
  this->ble_window_start_ = millis();
  this->fresh_telemetry_ = false;
#ifdef USE_WIFI
  ESP_LOGI(TAG, "BLE window: Wi-Fi off");
  wifi::global_wifi_component->disable();
  // Any existing BLE link was likely built while Wi-Fi was up and is degraded,
  // so drop it and let the client reconnect on a clean, Wi-Fi-free radio.
  this->disconnect();
#else
  ESP_LOGW(TAG, "exclusive_ble set but Wi-Fi is not compiled in; ignoring");
#endif
}

void OmnixComponent::close_ble_window_() {
  this->ble_window_open_ = false;
  this->fresh_telemetry_ = false;
  this->next_window_ms_ = millis() + this->update_interval_ms_;
#ifdef USE_WIFI
  ESP_LOGI(TAG, "BLE window: Wi-Fi on");
  if (wifi::global_wifi_component->is_disabled())
    wifi::global_wifi_component->enable();
#endif
}

bool OmnixComponent::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                         esp_ble_gattc_cb_param_t *param) {
  if (!BLEClientBase::gattc_event_handler(event, gattc_if, param))
    return false;

  switch (event) {
    case ESP_GATTC_SEARCH_CMPL_EVT: {
      auto *chr = this->get_characteristic(espbt::ESPBTUUID::from_uint16(OMNIX_SERVICE_UUID16),
                                           espbt::ESPBTUUID::from_raw(OMNIX_CHAR_UUID));
      if (chr == nullptr) {
        ESP_LOGW(TAG, "OmniX characteristic not found");
        this->char_found_ = false;
        break;
      }
      this->char_handle_ = chr->handle;
      this->char_found_ = true;
      ESP_LOGI(TAG, "Found OmniX characteristic (handle 0x%04X)", chr->handle);
      this->reset_session_();
      this->char_found_ = true;
      if (this->key_valid_) {
        this->start_auth_();
      } else {
        this->status_ = "invalid-key";
        ESP_LOGW(TAG, "Security key missing or invalid; set it from Home Assistant");
      }
      break;
    }
    case ESP_GATTC_WRITE_CHAR_EVT:
      if (this->char_found_ && param->write.handle == this->char_handle_)
        this->on_write_();
      break;
    case ESP_GATTC_READ_CHAR_EVT:
      if (this->char_found_ && param->read.handle == this->char_handle_)
        this->on_read_(param->read.value, param->read.value_len);
      break;
    case ESP_GATTC_DISCONNECT_EVT:
      this->reset_session_();
      break;
    default:
      break;
  }
  return true;
}

}  // namespace esphome::omnix

#endif  // USE_ESP32
