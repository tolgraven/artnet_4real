#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
// #include <stddef.h>

#if defined(ARDUINO)
#include <Arduino.h>
#else
#include <chrono>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>


#if defined(ARDUINO)
#define logf(f, ...) Serial.printf(f, ##__VA_ARGS__)
#else
#include "esp_log.h"
#define logf(f, ...) ESP_LOGI("artnet", f, ##__VA_ARGS__)
#endif


namespace anfr {

#if defined(ARDUINO)
inline uint32_t uptimeMs() { return millis(); }
#else
inline uint32_t uptimeMs() {
  // using namespace std::chrono;
  // return duration_cast<milliseconds>(steady_clock::now().time_since_epoch());
  using namespace std::chrono;
  uint32_t ms = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
  return ms; 
  // return 0UL;
}
#endif

class IPv4 { // stolen + cleaned from vtable and such, from Arduino's. Good to have own type for mult platform stuff
  public:
    IPv4(uint32_t ip = INADDR_NONE): data(ip) {}
    IPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d): data(a, b, c, d) {}
    IPv4(const uint8_t* ip): data(ip) {}
    IPv4(const IPv4& ip): IPv4(uint32_t(ip)) {}
    // bool operator==(const IPv4& addr) const { return *(*this) == *addr; }
    // bool operator==(const IPv4& addr) const { return data.dword == *addr; } // take it no need for this one since will cast to uint32_t on its own? getting ambigous overload so...
    bool operator==(const IPv4& addr) const { return data.dword == addr.data.dword; } // take it no need for this one since will cast to uint32_t on its own? getting ambigous overload so...
    // bool operator==(const uint8_t* addr) const { // XXX bad because IPV4 gets cast to uint32_t which then used as the address??
    //   return memcmp(addr, data.bytes, sizeof(data.bytes)) == 0;
    // };
    uint32_t operator*() const { return data.dword; }
    operator uint32_t() const { return data.dword; }
    explicit operator bool()  const { return data.dword != INADDR_NONE; } // this was causing me mad issues when modding (then forgetting about having done so) IPAddress haha! no const = cast becomes assignment, const = breaks == operator(!!) which is nonsense bc why would it attempt to bounce down to bool to compare stuff?? optimizing "both false?" or w/e would happen out of sight soo. where are you, ghost mentor?
    uint8_t operator[](int index) const { return data.bytes[index]; }
    uint8_t& operator[](int index)      { return data.bytes[index]; }
    // Overloaded copy operators to allow initialisation of IPv4 objects from other types
    IPv4& operator=(const uint8_t* ip) { memcpy(data.bytes, ip, sizeof(data.bytes)); return *this; }
    IPv4& operator=(uint32_t ip) { data.dword = ip; return *this; }

    static IPv4 NONE() { return IPv4(); }
    static IPv4 ANY() { return IPv4((uint32_t)0); }
  private:
    union Data {
      uint8_t bytes[4];   // IPv4 address
      uint32_t dword = 0;
      Data(uint32_t ip): dword(ip) {}
      Data(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        bytes[0] = a; bytes[1] = b; bytes[2] = c; bytes[3] = d;
      };
      // Data(const uint8_t* ip) { memcpy(bytes, ip, sizeof(bytes)); }
      Data(const uint8_t* ip): dword(*(uint32_t*)ip) {}
    } data;

public: // but for Arduino should prob handle the normal type, eh...
#if defined(ARDUINO)  // etc then add other code for other platforms
    IPv4(const IPAddress& ip): IPv4(uint32_t(ip)) {}
    // bool operator==(const IPAddress& ip) const { return *(*this) == uint32_t(ip); }
    IPv4& operator=(const IPAddress& ip) { data.dword = uint32_t(ip); return *this; }
    operator IPAddress() const { return IPAddress(data.dword); }
#endif
};



}
