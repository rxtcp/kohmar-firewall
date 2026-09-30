add_executable(
        som_demo
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        ${PROJECT_SOURCE_DIR}/resources/resources.qrc
)

target_include_directories(
        som_demo
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/libs
)

target_link_libraries(
        som_demo
        PRIVATE
        som
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
)

target_compile_features(som_demo PRIVATE cxx_std_23)

install(
        TARGETS som_demo
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)