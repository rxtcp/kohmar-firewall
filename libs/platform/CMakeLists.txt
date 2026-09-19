add_library(platform STATIC)

target_sources(
        platform
        PRIVATE
        config/ConfigReader.cpp
        config/ConfigReader.h

        logging/Logger.cpp
        logging/Logger.h
        logging/NullLogger.cpp
        logging/NullLogger.h
        logging/PrintfLogger.cpp
        logging/PrintfLogger.h
        logging/SyslogLogger.cpp
        logging/SyslogLogger.h

        sockets/LowLevelSocket.cpp
        sockets/LowLevelSocket.h
        sockets/UnixLowLevelSocket.cpp
        sockets/UnixLowLevelSocket.h

        threading/LowLevelThread.cpp
        threading/LowLevelThread.h
        threading/Pool.cpp
        threading/Pool.h
        threading/PosixThread.cpp
        threading/PosixThread.h
        threading/Semaphore.cpp
        threading/Semaphore.h
        threading/Signal.cpp
        threading/Signal.h
        threading/SocketSignal.cpp
        threading/SocketSignal.h
        threading/StdThread.cpp
        threading/StdThread.h
        threading/Thread.cpp
        threading/Thread.h
        threading/UnixSemaphore.cpp
        threading/UnixSemaphore.h

        services/DaemonService.cpp
        services/DaemonService.h
        services/Service.cpp
        services/Service.h

        PlatformFactory.cpp
        PlatformFactory.h
)

target_include_directories(
        platform
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/config
        ${CMAKE_CURRENT_SOURCE_DIR}/logging
        ${CMAKE_CURRENT_SOURCE_DIR}/sockets
        ${CMAKE_CURRENT_SOURCE_DIR}/threading
        ${CMAKE_CURRENT_SOURCE_DIR}/services
)

target_link_libraries(
        platform
        PUBLIC
        Qt${QT_VERSION_MAJOR}::Core
        Threads::Threads
)

target_compile_features(platform PUBLIC cxx_std_17)

set_target_properties(
        platform
        PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)