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
        Qt6::Core
        Qt6::Network
)

target_compile_features(networking PUBLIC cxx_std_23)