add_library(firewall_protocol INTERFACE)

target_sources(
        firewall_protocol
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/firewall/protocol.h
)

target_include_directories(
        firewall_protocol
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)