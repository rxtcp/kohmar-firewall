add_library(storage STATIC)

target_sources(
        storage
        PRIVATE
        dbmanager.cpp
        dbmanager.h
)

target_include_directories(
        storage
        PUBLIC
        ${PROJECT_SOURCE_DIR}/libs
)

target_link_libraries(
        storage
        PUBLIC
        firewall_types
        networking
        Qt6::Core
        Qt6::Widgets
        Qt6::Sql
)

target_compile_features(storage PUBLIC cxx_std_23)