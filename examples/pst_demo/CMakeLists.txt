add_executable(
        pst_demo
        main.cpp
)

target_include_directories(
        pst_demo
        PRIVATE
        ${PROJECT_SOURCE_DIR}/libs
)

target_link_libraries(
        pst_demo
        PRIVATE
        pst
        Qt6::Core
)

target_compile_features(pst_demo PRIVATE cxx_std_23)

install(
        TARGETS pst_demo
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)