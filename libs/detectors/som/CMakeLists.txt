add_library(som STATIC)

target_sources(
        som
        PRIVATE
        neuron.cpp
        neuron.h
        samplesom.cpp
        samplesom.h
        selforganizedmap.cpp
        selforganizedmap.h
)

target_include_directories(
        som
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/libs/detectors
)

target_link_libraries(
        som
        PUBLIC
        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Widgets
)

target_compile_features(som PUBLIC cxx_std_17)