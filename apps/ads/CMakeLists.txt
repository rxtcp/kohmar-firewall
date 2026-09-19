cmake_minimum_required(VERSION 3.16)
project(ADS VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Set up AUTOMOC and some sensible defaults for runtime execution
# When using Qt 6.3, you can replace the code block below with
# qt_standard_project_setup()
set(CMAKE_AUTOMOC ON)
include(GNUInstallDirs)
set(CMAKE_AUTOUIC ON)

find_package(QT NAMES Qt5 Qt6 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Gui Network Sql)
find_package(Qt${QT_VERSION_MAJOR} OPTIONAL_COMPONENTS Widgets)

qt_add_executable(ADS WIN32 MACOSX_BUNDLE
        ../../legacy/common/ConnectionTree.cpp ../../legacy/common/ConnectionTree.h
        ../../libs/networking/adressresolver.cpp ../../libs/networking/adressresolver.h
        ../../libs/storage/dbmanager.cpp ../../libs/storage/dbmanager.h
        ../../libs/kernel_client/netlinkmanager.cpp ../../libs/kernel_client/netlinkmanager.h
        ../../libs/engine/packsreceiver.cpp ../../libs/engine/packsreceiver.h
        ../../libs/engine/structs.h
        ../../libs/platform/config/ConfigReader.cpp
        ../../libs/platform/service/DaemonService.cpp ../../libs/platform/service/DaemonService.h
        ../../libs/platform/logging/Logger.cpp ../../libs/platform/logging/Logger.h
        ../../libs/platform/sockets/LowLevelSocket.cpp ../../libs/platform/sockets/LowLevelSocket.h
        ../../libs/platform/threading/LowLevelThread.cpp ../../libs/platform/threading/LowLevelThread.h
        ../../libs/platform/logging/NullLogger.cpp ../../libs/platform/logging/NullLogger.h
        ../../libs/platform/PlatformFactory.cpp ../../libs/platform/PlatformFactory.h
        ../../libs/platform/threading/Pool.cpp ../../libs/platform/threading/Pool.h
        ../../libs/platform/threading/PosixThread.cpp ../../libs/platform/threading/PosixThread.h
        ../../libs/platform/logging/PrintfLogger.cpp ../../libs/platform/logging/PrintfLogger.h
        ../../libs/platform/threading/Semaphore.cpp ../../libs/platform/threading/Semaphore.h
        ../../libs/platform/service/Service.cpp ../../libs/platform/service/Service.h
        ../../libs/platform/threading/Signal.cpp ../../libs/platform/threading/Signal.h
        ../../libs/platform/threading/SocketSignal.cpp ../../libs/platform/threading/SocketSignal.h
        ../../libs/platform/threading/StdThread.cpp ../../libs/platform/threading/StdThread.h
        ../../libs/platform/logging/SyslogLogger.cpp ../../libs/platform/logging/SyslogLogger.h
        ../../libs/platform/threading/Thread.cpp ../../libs/platform/threading/Thread.h
        ../../libs/platform/sockets/UnixLowLevelSocket.cpp ../../libs/platform/sockets/UnixLowLevelSocket.h
        ../../libs/platform/threading/UnixSemaphore.cpp ../../libs/platform/threading/UnixSemaphore.h
        ../../libs/detectors/pst/pst_arithpredictor.cpp ../../libs/detectors/pst/pst_arithpredictor.h
        ../../libs/detectors/pst/pst_builder.cpp ../../libs/detectors/pst/pst_builder.h
        ../../libs/detectors/pst/pst_common.h
        ../../libs/detectors/pst/pst_context.cpp ../../libs/detectors/pst/pst_context.h
        ../../libs/detectors/pst/pst_node.cpp ../../libs/detectors/pst/pst_node.h
        ../../libs/detectors/pst/pst_predictor.cpp ../../libs/detectors/pst/pst_predictor.h
        ../../libs/detectors/pst/pst_samples.cpp ../../libs/detectors/pst/pst_samples.h
        ../../libs/detectors/som/neuron.cpp ../../libs/detectors/som/neuron.h
        ../../libs/detectors/som/samplesom.cpp ../../libs/detectors/som/samplesom.h
        ../../libs/detectors/som/selforganizedmap.cpp ../../libs/detectors/som/selforganizedmap.h
        ui/rules/addruleform.cpp ui/rules/addruleform.h ui/rules/addruleform.ui
        ui/settings/ads_settings_dialog.cpp ui/settings/ads_settings_dialog.h ui/settings/ads_settings_dialog.ui
        ui/anomalies/anomaly_frame.cpp ui/anomalies/anomaly_frame.h
        ui/anomalies/anomaly_reader_flow.cpp ui/anomalies/anomaly_reader_flow.h
        ui/anomalies/anomaly_reader_tcp.cpp ui/anomalies/anomaly_reader_tcp.h
        ui/learning/learning_flow_dialog.cpp ui/learning/learning_flow_dialog.h ui/learning/learning_flow_dialog.ui
        ui/learning/learning_tcp_dialog.cpp ui/learning/learning_tcp_dialog.h ui/learning/learning_tcp_dialog.ui
        main.cpp
        ui/mainwindow.cpp ui/mainwindow.h ui/mainwindow.ui
        ui/rules/rulesform.cpp ui/rules/rulesform.h ui/rules/rulesform.ui
)
target_link_libraries(ADS PRIVATE
        Qt::Core
        Qt::Gui
        Qt::Network
        Qt::Sql
)

target_compile_options(ADS
        -g
)

if ((QT_VERSION_MAJOR GREATER 4))
    target_link_libraries(ADS PRIVATE
            Qt::Widgets
    )
endif ()

install(TARGETS ADS
        BUNDLE DESTINATION ../../AAA/ADS
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Consider using qt_generate_deploy_app_script() for app deployment if
# the project can use Qt 6.3. In that case rerun qmake2cmake with
# --min-qt-version=6.3.
