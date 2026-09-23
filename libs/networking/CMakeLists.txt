add_library(networking STATIC)

target_sources(
        networking
        PRIVATE
        addressresolver.cpp
        addressresolver.h
)

target_include_directories(
        networking
        PUBLIC
        ${PROJECT_SOURCE_DIR}/libs
)

target_link_libraries(
        networking
        PUBLIC
        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Network
)

target_compile_features(networking PUBLIC cxx_std_17)