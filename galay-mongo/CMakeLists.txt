find_package(galay-kernel CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_path(SPDLOG_INCLUDE_DIR spdlog/spdlog.h REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB SOURCES "base/*.cc" "protocol/*.cc" "async/*.cc" "sync/*.cc")

if(NOT TARGET galay-kernel::galay-kernel)
    message(FATAL_ERROR "galay-kernel::galay-kernel target not found. Please check galay-kernel installation and CMake config.")
endif()

set_property(TARGET galay-kernel::galay-kernel PROPERTY SYSTEM ON)
if(TARGET OpenSSL::SSL)
    set_property(TARGET OpenSSL::SSL PROPERTY SYSTEM ON)
endif()
if(TARGET OpenSSL::Crypto)
    set_property(TARGET OpenSSL::Crypto PROPERTY SYSTEM ON)
endif()
if(TARGET spdlog::spdlog)
    set_property(TARGET spdlog::spdlog PROPERTY SYSTEM ON)
endif()
if(TARGET spdlog::spdlog_header_only)
    set_property(TARGET spdlog::spdlog_header_only PROPERTY SYSTEM ON)
endif()

add_library(${PROJECT_NAME} ${GALAY_MONGO_LIBRARY_TYPE} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
    PUBLIC galay-kernel::galay-kernel
    PUBLIC OpenSSL::SSL
    PUBLIC OpenSSL::Crypto
    PUBLIC pthread
)

target_include_directories(${PROJECT_NAME}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
    PUBLIC $<INSTALL_INTERFACE:include>
)
target_include_directories(${PROJECT_NAME}
    SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR}
                  ${SPDLOG_INCLUDE_DIR}
)

galay_mongo_apply_cxx(${PROJECT_NAME})

if(GALAY_MONGO_IMPORT_COMPILATION_ENABLED AND CMAKE_VERSION VERSION_GREATER_EQUAL 3.28)
    add_library(${PROJECT_NAME}-modules STATIC)
    target_link_libraries(${PROJECT_NAME}-modules PUBLIC ${PROJECT_NAME})
    target_include_directories(${PROJECT_NAME}-modules
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
        PUBLIC $<INSTALL_INTERFACE:include>
    )
    target_include_directories(${PROJECT_NAME}-modules
        SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR}
                      ${SPDLOG_INCLUDE_DIR}
    )
    galay_mongo_apply_cxx(${PROJECT_NAME}-modules)
    target_sources(${PROJECT_NAME}-modules
        PUBLIC
            FILE_SET CXX_MODULES
            FILES ${CMAKE_CURRENT_SOURCE_DIR}/module/galay.mongo.cppm
    )
    if(GALAY_MONGO_IMPORT_COMPILE_OPTIONS)
        target_compile_options(${PROJECT_NAME}-modules PUBLIC ${GALAY_MONGO_IMPORT_COMPILE_OPTIONS})
    endif()
endif()

install(TARGETS ${PROJECT_NAME}
    EXPORT galay-mongo-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

if(TARGET ${PROJECT_NAME}-modules AND GALAY_MONGO_INSTALL_MODULE_INTERFACE)
    install(TARGETS ${PROJECT_NAME}-modules
        EXPORT galay-mongo-targets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        FILE_SET CXX_MODULES DESTINATION include/galay-mongo/module
    )
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION include/galay-mongo
    FILES_MATCHING
    PATTERN "*.h"
    PATTERN "*.hpp"
    PATTERN "*.inl"
    PATTERN "build" EXCLUDE
    PATTERN "CMakeFiles" EXCLUDE
    PATTERN "*.cc" EXCLUDE
    PATTERN "*.cmake" EXCLUDE
)

if(GALAY_MONGO_INSTALL_MODULE_INTERFACE AND NOT GALAY_MONGO_IMPORT_COMPILATION_ENABLED)
    file(GLOB GALAY_MONGO_MODULE_INTERFACE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/module/*.cppm")
    if(GALAY_MONGO_MODULE_INTERFACE_FILES)
        install(FILES ${GALAY_MONGO_MODULE_INTERFACE_FILES}
            DESTINATION include/galay-mongo/module
        )
    endif()
endif()

install(EXPORT galay-mongo-targets
    FILE GalayMongoTargets.cmake
    NAMESPACE galay-mongo::
    DESTINATION lib/cmake/galay-mongo
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/galay-mongo-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/GalayMongoConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/galay-mongo-config.cmake"
    INSTALL_DESTINATION lib/cmake/galay-mongo
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/galay-mongo-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/galay-mongo-config-version.cmake"
    DESTINATION lib/cmake/galay-mongo
)
