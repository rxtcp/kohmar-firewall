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
        ${PROJECT_SOURCE_DIR}/libs
)

target_link_libraries(
        som
        PUBLIC
        Qt6::Core
        Qt6::Widgets
)

target_compile_features(som PUBLIC cxx_std_23)