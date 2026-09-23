add_library(kernel_client STATIC)

target_sources(
        kernel_client
        PRIVATE
        netlinkmanager.cpp
        netlinkmanager.h
)

target_include_directories(
        kernel_client
        PUBLIC
        ${PROJECT_SOURCE_DIR}/libs
)

target_link_libraries(
        kernel_client
        PUBLIC
        firewall_types
        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Widgets
        Threads::Threads
)

target_compile_features(kernel_client PUBLIC cxx_std_17)