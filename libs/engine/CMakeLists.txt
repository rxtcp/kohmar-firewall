add_library(firewall_types INTERFACE)

target_sources(
        firewall_types
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/structs.h
        ${CMAKE_CURRENT_SOURCE_DIR}/config.h
)

target_include_directories(
        firewall_types
        INTERFACE
        ${PROJECT_SOURCE_DIR}/libs
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(
        firewall_types
        INTERFACE
        Qt${QT_VERSION_MAJOR}::Core
        platform
)

add_library(engine STATIC)

target_sources(
        engine
        PRIVATE
        packsreceiver.cpp
        packsreceiver.h
)

target_include_directories(
        engine
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/libs
)

target_compile_definitions(
        engine
        PRIVATE
        ADS_QT
)

target_link_libraries(
        engine
        PUBLIC
        firewall_types
        platform
        pst
        som
        Qt${QT_VERSION_MAJOR}::Core
        Threads::Threads
)

target_compile_features(engine PUBLIC cxx_std_17)