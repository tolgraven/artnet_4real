#pragma once

// fix tot free from arduino tho
#if defined(ARDUINO)
#include <Arduino.h>
#endif

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP32)
#include <WiFi.h>
#elif defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#elif defined(ARDUINO_ARCH_SAMD)
#if defined(ARDUINO_SAMD_MKR1000)
#include <WiFi101.h>
#else
#include <WiFiNINA.h>
#endif
// #else
// #error "Architecture not supported!"
#endif

namespace an4r::artnet {
//
// unsigned long timestampMs() {
// #if defined(ARDUIINO)
//   return millis();
// #else
// // #include <chrono>
// //   return std::chrono::steady_clock yada
// #endif
//   return 0UL;
// }

}
