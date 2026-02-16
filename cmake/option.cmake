include_guard(GLOBAL)

option(GALAY_MONGO_BUILD_TESTS "Build galay-mongo tests" ON)
option(GALAY_MONGO_BUILD_EXAMPLES "Build galay-mongo examples" ON)
option(GALAY_MONGO_BUILD_BENCHMARKS "Build galay-mongo benchmarks" ON)
option(GALAY_MONGO_BUILD_SHARED_LIBS "Build galay-mongo as a shared library" ON)
option(GALAY_MONGO_CXX_EXTENSIONS "Enable compiler-specific C++ extensions" OFF)
option(GALAY_MONGO_INSTALL_MODULE_INTERFACE "Install C++ module interface files (*.cppm)" ON)
option(GALAY_MONGO_ENABLE_IMPORT_COMPILATION "Enable C++ import/module compilation path" ON)
option(GALAY_MONGO_BUILD_MODULE_EXAMPLES "Build examples that use import/module syntax" ON)

if(DEFINED GALAY_MONGO_BUILD_IMPORT_EXAMPLES)
    message(DEPRECATION "GALAY_MONGO_BUILD_IMPORT_EXAMPLES is deprecated. "
                        "Use GALAY_MONGO_BUILD_MODULE_EXAMPLES instead.")
    set(GALAY_MONGO_BUILD_MODULE_EXAMPLES
        "${GALAY_MONGO_BUILD_IMPORT_EXAMPLES}"
        CACHE BOOL "Build examples that use import/module syntax" FORCE)
endif()

set(GALAY_MONGO_CXX_STANDARD "23" CACHE STRING "C++ standard for galay-mongo targets")
set_property(CACHE GALAY_MONGO_CXX_STANDARD PROPERTY STRINGS 20 23 26)

if(GALAY_MONGO_BUILD_SHARED_LIBS)
    set(GALAY_MONGO_LIBRARY_TYPE SHARED)
else()
    set(GALAY_MONGO_LIBRARY_TYPE STATIC)
endif()

set(GALAY_MONGO_IMPORT_BUILD_AVAILABLE OFF)
set(GALAY_MONGO_IMPORT_COMPILE_OPTIONS "")
set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON "")
set(GALAY_MONGO_CLANG_SCAN_DEPS "")

if(CMAKE_VERSION VERSION_LESS 3.28)
    set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON "CMake < 3.28")
else()
    if(NOT CMAKE_GENERATOR MATCHES "Ninja|Visual Studio")
        set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON "unsupported generator; require Ninja or Visual Studio")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
            set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON "current stable GNU path is Linux only")
        elseif(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
            set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON "GCC < 14")
        else()
            set(GALAY_MONGO_IMPORT_BUILD_AVAILABLE ON)
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        find_program(GALAY_MONGO_CLANG_SCAN_DEPS NAMES clang-scan-deps)
        if(NOT GALAY_MONGO_CLANG_SCAN_DEPS)
            get_filename_component(_GALAY_MONGO_CLANG_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
            if(EXISTS "${_GALAY_MONGO_CLANG_BIN_DIR}/clang-scan-deps")
                set(GALAY_MONGO_CLANG_SCAN_DEPS "${_GALAY_MONGO_CLANG_BIN_DIR}/clang-scan-deps")
            else()
                find_program(GALAY_MONGO_CLANG_SCAN_DEPS NAMES clang-scan-deps HINTS "${_GALAY_MONGO_CLANG_BIN_DIR}")
            endif()
        endif()
        if(NOT GALAY_MONGO_CLANG_SCAN_DEPS)
            set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON "clang-scan-deps not found")
        elseif(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
            set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON "AppleClang is not supported for module dependency scanning in this project")
        else()
            set(GALAY_MONGO_IMPORT_BUILD_AVAILABLE ON)
            list(APPEND GALAY_MONGO_IMPORT_COMPILE_OPTIONS -Xclang -fskip-odr-check-in-gmf)
        endif()
    else()
        set(GALAY_MONGO_IMPORT_UNAVAILABLE_REASON
            "unsupported compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    endif()
endif()

set(GALAY_MONGO_IMPORT_COMPILATION_ENABLED OFF)
if(GALAY_MONGO_ENABLE_IMPORT_COMPILATION AND GALAY_MONGO_IMPORT_BUILD_AVAILABLE)
    set(GALAY_MONGO_IMPORT_COMPILATION_ENABLED ON)
elseif(GALAY_MONGO_ENABLE_IMPORT_COMPILATION AND NOT GALAY_MONGO_IMPORT_BUILD_AVAILABLE)
    message(STATUS "GALAY_MONGO_ENABLE_IMPORT_COMPILATION=ON but toolchain is unsupported. "
                   "Import compilation is disabled. "
                   "Requirement: CMake >= 3.28, Ninja/Visual Studio generator, Linux + GCC >= 14. "
                   "Current: ${CMAKE_SYSTEM_NAME}, ${CMAKE_GENERATOR}, ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}. "
                   "Reason: ${GALAY_MONGO_IMPORT_UNAVAILABLE_REASON}.")
endif()

if(GALAY_MONGO_IMPORT_COMPILATION_ENABLED)
    set(CMAKE_CXX_SCAN_FOR_MODULES ON CACHE BOOL
        "Enable C++ module dependency scanning when import compilation is enabled" FORCE)
endif()

set(GALAY_MONGO_BUILD_MODULE_EXAMPLES_EFFECTIVE OFF)
if(GALAY_MONGO_BUILD_MODULE_EXAMPLES AND GALAY_MONGO_IMPORT_COMPILATION_ENABLED)
    set(GALAY_MONGO_BUILD_MODULE_EXAMPLES_EFFECTIVE ON)
elseif(GALAY_MONGO_BUILD_MODULE_EXAMPLES)
    message(STATUS "GALAY_MONGO_BUILD_MODULE_EXAMPLES=ON but import compilation is disabled.")
endif()

set(GALAY_MONGO_BUILD_IMPORT_EXAMPLES_EFFECTIVE ${GALAY_MONGO_BUILD_MODULE_EXAMPLES_EFFECTIVE})

function(galay_mongo_apply_cxx target_name)
    set_target_properties(${target_name} PROPERTIES
        CXX_STANDARD ${GALAY_MONGO_CXX_STANDARD}
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS ${GALAY_MONGO_CXX_EXTENSIONS}
    )
endfunction()
