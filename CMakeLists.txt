cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


if(${ESP_PLATFORM}) # && as_component...
    message(STATUS "Compiling for ESP-IDF")
    # include($ENV{IDF_PATH}/tools/cmake/project.cmake)

    idf_component_register(SRCS src/artnet4real.cpp src/components.cpp
                          INCLUDE_DIRS src
                          )
  target_compile_options(${COMPONENT_LIB} PRIVATE
      -DESP32
      -Wno-error
      -Wno-extra
      -Wno-maybe-uninitialized
      -std=gnu++17
      )
  add_compile_options (-Wno-error)

  include($ENV{IDF_PATH}/tools/cmake/project.cmake)

else()
  message(STATUS "Compiling for Host Platform")

  add_library(artnet4real STATIC src/artnet4real.cpp src/components.cpp)
  target_include_directories(artnet4real PUBLIC src)

  include_directories(SYSTEM /Users/tol/.espressif/tools/xtensa-esp32-elf/esp-2021r2-8.2.0/xtensa-esp32-elf/xtensa-esp32-elf/sys-include)

  if(${APPLE})
      include_directories(SYSTEM /usr/local/include)
      link_directories(/usr/local/lib)
      # include_directories(SYSTEM /Users/tol/.espressif/tools/xtensa-esp32-elf/esp-2019r2-8.2.0/xtensa-esp32-elf/xtensa-esp32-elf/sys-include)
      # link_directories(/Users/tol/.espressif/tools/xtensa-esp32-elf/esp-2019r2-8.2.0/xtensa-esp32-elf/xtensa-esp32-elf/lib)
  endif()
#     add_subdirectory(mock-idf)
project("artnet4real")
endif()


