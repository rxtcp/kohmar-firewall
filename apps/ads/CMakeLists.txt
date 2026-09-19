set(ADS_UI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ui)

add_executable(
        ads
        main.cpp

        ${ADS_UI_DIR}/mainwindow.cpp
        ${ADS_UI_DIR}/mainwindow.h
        ${ADS_UI_DIR}/mainwindow.ui

        ${ADS_UI_DIR}/rules/rulesform.cpp
        ${ADS_UI_DIR}/rules/rulesform.h
        ${ADS_UI_DIR}/rules/rulesform.ui

        ${ADS_UI_DIR}/rules/addruleform.cpp
        ${ADS_UI_DIR}/rules/addruleform.h
        ${ADS_UI_DIR}/rules/addruleform.ui

        ${ADS_UI_DIR}/settings/ads_settings_dialog.cpp
        ${ADS_UI_DIR}/settings/ads_settings_dialog.h
        ${ADS_UI_DIR}/settings/ads_settings_dialog.ui

        ${ADS_UI_DIR}/learning/learning_tcp_dialog.cpp
        ${ADS_UI_DIR}/learning/learning_tcp_dialog.h
        ${ADS_UI_DIR}/learning/learning_tcp_dialog.ui

        ${ADS_UI_DIR}/learning/learning_flow_dialog.cpp
        ${ADS_UI_DIR}/learning/learning_flow_dialog.h
        ${ADS_UI_DIR}/learning/learning_flow_dialog.ui

        ${ADS_UI_DIR}/anomalies/anomaly_frame.cpp
        ${ADS_UI_DIR}/anomalies/anomaly_frame.h

        ${ADS_UI_DIR}/anomalies/anomaly_reader_tcp.cpp
        ${ADS_UI_DIR}/anomalies/anomaly_reader_tcp.h

        ${ADS_UI_DIR}/anomalies/anomaly_reader_flow.cpp
        ${ADS_UI_DIR}/anomalies/anomaly_reader_flow.h

        ${PROJECT_SOURCE_DIR}/resources/resources.qrc
)

target_include_directories(
        ads
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${ADS_UI_DIR}
        ${ADS_UI_DIR}/rules
        ${ADS_UI_DIR}/settings
        ${ADS_UI_DIR}/learning
        ${ADS_UI_DIR}/anomalies
        ${PROJECT_SOURCE_DIR}/libs
)

target_compile_definitions(
        ads
        PRIVATE
        ADS_QT
)

target_link_libraries(
        ads
        PRIVATE
        engine
        kernel_client
        storage
        networking
        platform
        pst
        som
        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Gui
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Network
        Qt${QT_VERSION_MAJOR}::Sql
        Threads::Threads
)

set_property(
        TARGET ads
        PROPERTY AUTOUIC_SEARCH_PATHS
        ${ADS_UI_DIR}
        ${ADS_UI_DIR}/rules
        ${ADS_UI_DIR}/settings
        ${ADS_UI_DIR}/learning
)

install(
        TARGETS ads
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
        DIRECTORY ${PROJECT_SOURCE_DIR}/data/samples/ads/
        DESTINATION ${CMAKE_INSTALL_DATADIR}/kohmar-firewall/samples
)

install(
        FILES
        ${PROJECT_SOURCE_DIR}/config/ads.settings.example
        ${PROJECT_SOURCE_DIR}/config/readerd.conf.example
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/kohmar-firewall
)