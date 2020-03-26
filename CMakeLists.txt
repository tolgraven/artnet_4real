
set(CMAKE_CXX_STANDARD 17)
set(COMPONENT_ADD_INCLUDEDIRS src)
set(COMPONENT_SRCS src/artnet4real.cpp)
set(COMPONENT_REQUIRES arduino)
# idf_component_register()
# register_component()

idf_component_register(SRCS src/artnet4real.cpp
                       INCLUDE_DIRS src
                       REQUIRES arduino)
                     # get rid of IPAddress, use chrono then pretty much done w arduino right?
target_compile_options(${COMPONENT_LIB} PRIVATE
    -DESP32
    -DARDUINO_ARCH_ESP32
    -DARDUINO
    -Wno-error
    )
