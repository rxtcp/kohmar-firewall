cmake_minimum_required(VERSION 3.20)

project(
        kohmar_firewall
        VERSION 1.0.0
        DESCRIPTION "Anomaly Detection System for network traffic"
        LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include(GNUInstallDirs)

if (NOT DEFINED CMAKE_INSTALL_RUNSTATEDIR)
    set(
            CMAKE_INSTALL_RUNSTATEDIR
            "${CMAKE_INSTALL_LOCALSTATEDIR}/run"
    )
endif ()

configure_file(
        ${PROJECT_SOURCE_DIR}/cmake/install_paths.h.in
        ${PROJECT_BINARY_DIR}/generated/firewall/install_paths.h
        @ONLY
)

option(BUILD_EXAMPLES "Build PST and SOM demonstration applications" ON)
option(BUILD_TESTING "Build project tests" OFF)

find_package(
        Qt6
        REQUIRED COMPONENTS
        Core
        Gui
        Widgets
        Network
        Sql
)

find_package(Threads REQUIRED)

add_subdirectory(libs/protocol)
add_subdirectory(libs/platform)
add_subdirectory(libs/detectors/pst)
add_subdirectory(libs/detectors/som)
add_subdirectory(libs/networking)
add_subdirectory(libs/engine)
add_subdirectory(libs/kernel_client)
add_subdirectory(libs/storage)

add_subdirectory(apps/drvctl)
add_subdirectory(apps/ads)

if (BUILD_EXAMPLES)
    add_subdirectory(examples/pst_demo)
    add_subdirectory(examples/som_demo)
endif ()

if (BUILD_TESTING)
    enable_testing()

    if (EXISTS "${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt")
        add_subdirectory(tests)
    endif ()
endif ()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_custom_target(
            ads_netfilter_module
            COMMAND ${CMAKE_MAKE_PROGRAM}
            WORKING_DIRECTORY
            ${PROJECT_SOURCE_DIR}/kernel/ads_netfilter
            COMMENT "Building ads_netfilter Linux kernel module"
            USES_TERMINAL
    )
endif ()