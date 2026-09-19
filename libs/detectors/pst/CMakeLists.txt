add_library(pst STATIC)

target_sources(
        pst
        PRIVATE
        pst_arithpredictor.cpp
        pst_arithpredictor.h
        pst_builder.cpp
        pst_builder.h
        pst_common.h
        pst_context.cpp
        pst_context.h
        pst_node.cpp
        pst_node.h
        pst_predictor.cpp
        pst_predictor.h
        pst_samples.cpp
        pst_samples.h
)

target_include_directories(
        pst
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/libs/detectors
)

target_link_libraries(
        pst
        PUBLIC
        Qt${QT_VERSION_MAJOR}::Core
)

target_compile_features(pst PUBLIC cxx_std_17)