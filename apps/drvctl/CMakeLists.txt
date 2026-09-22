add_executable(
        ads_drvctl
        ads_drvctl.cpp
)

target_include_directories(
        ads_drvctl
        PRIVATE
        ${PROJECT_SOURCE_DIR}/libs
)

target_link_libraries(
        ads_drvctl
        PRIVATE
        platform
        Threads::Threads
)

target_compile_features(ads_drvctl PRIVATE cxx_std_17)

install(
        TARGETS ads_drvctl
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(
        FILES ../../config/module.conf.example
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/kohmar-firewall
)