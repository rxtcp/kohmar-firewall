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
        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Gui
        Qt${QT_VERSION_MAJOR}::Widgets
)

target_compile_features(som_demo PRIVATE cxx_std_17)

install(
        TARGETS som_demo
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)