cmake_minimum_required(VERSION 3.20)
project(ADS VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOMOC ON)
include(GNUInstallDirs)
set(CMAKE_AUTOUIC ON)

find_package(Qt5 5.15 REQUIRED COMPONENTS Core Gui Widgets Network Sql)
find_package(Threads REQUIRED)

add_executable(ADS
    ../Common/ConnectionTree.cpp ../Common/ConnectionTree.h
    ../Common/adressresolver.cpp ../Common/adressresolver.h
    ../Common/dbmanager.cpp ../Common/dbmanager.h
    ../Common/netlinkmanager.cpp ../Common/netlinkmanager.h
    ../Common/packsreceiver.cpp ../Common/packsreceiver.h
    ../Common/rb_connection_tree.h
    ../Common/structs.h
    ../Common/utils/ConfigReader.cpp
    ../Common/utils/DaemonService.cpp ../Common/utils/DaemonService.h
    ../Common/utils/Logger.cpp ../Common/utils/Logger.h
    ../Common/utils/LowLevelSocket.cpp ../Common/utils/LowLevelSocket.h
    ../Common/utils/LowLevelThread.cpp ../Common/utils/LowLevelThread.h
    ../Common/utils/NullLogger.cpp ../Common/utils/NullLogger.h
    ../Common/utils/PlatformFactory.cpp ../Common/utils/PlatformFactory.h
    ../Common/utils/Pool.cpp ../Common/utils/Pool.h
    ../Common/utils/PosixThread.cpp ../Common/utils/PosixThread.h
    ../Common/utils/PrintfLogger.cpp ../Common/utils/PrintfLogger.h
    ../Common/utils/Semaphore.cpp ../Common/utils/Semaphore.h
    ../Common/utils/Service.cpp ../Common/utils/Service.h
    ../Common/utils/Signal.cpp ../Common/utils/Signal.h
    ../Common/utils/SocketSignal.cpp ../Common/utils/SocketSignal.h
    ../Common/utils/StdThread.cpp ../Common/utils/StdThread.h
    ../Common/utils/SyslogLogger.cpp ../Common/utils/SyslogLogger.h
    ../Common/utils/Thread.cpp ../Common/utils/Thread.h
    ../Common/utils/UnixLowLevelSocket.cpp ../Common/utils/UnixLowLevelSocket.h
    ../Common/utils/UnixSemaphore.cpp ../Common/utils/UnixSemaphore.h
    ../PST/pst_arithpredictor.cpp ../PST/pst_arithpredictor.h
    ../PST/pst_builder.cpp ../PST/pst_builder.h
    ../PST/pst_common.h
    ../PST/pst_context.cpp ../PST/pst_context.h
    ../PST/pst_node.cpp ../PST/pst_node.h
    ../PST/pst_predictor.cpp ../PST/pst_predictor.h
    ../PST/pst_samples.cpp ../PST/pst_samples.h
    ../SOM/neuron.cpp ../SOM/neuron.h
    ../SOM/samplesom.cpp ../SOM/samplesom.h
    ../SOM/selforganizedmap.cpp ../SOM/selforganizedmap.h
    addruleform.cpp addruleform.h addruleform.ui
    ads_settings_dialog.cpp ads_settings_dialog.h ads_settings_dialog.ui
    anomaly_frame.cpp anomaly_frame.h
    anomaly_reader_flow.cpp anomaly_reader_flow.h
    anomaly_reader_tcp.cpp anomaly_reader_tcp.h
    learning_flow_dialog.cpp learning_flow_dialog.h learning_flow_dialog.ui
    learning_tcp_dialog.cpp learning_tcp_dialog.h learning_tcp_dialog.ui
    main.cpp
    mainwindow.cpp mainwindow.h mainwindow.ui
    rulesform.cpp rulesform.h rulesform.ui
)
target_link_libraries(ADS PRIVATE
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Network
    Qt5::Sql
    Threads::Threads
)

target_compile_features(ADS PRIVATE cxx_std_23)
# PST still contains a variable-length array; preserve this legacy extension until tested.
set_target_properties(ADS PROPERTIES CXX_EXTENSIONS ON)

install(TARGETS ADS
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
