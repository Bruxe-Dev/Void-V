cmake_minimum_required(VERSION 3.15)

project(
    VoidVault
    DESCRIPTION "Local Configuration and Credential Protection Agent"
    VERSION 2.0.0
    LANGUAGES CXX 
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

option(
    VOID_VAULT_BUILD_TESTS
    "Build local vault tests"
    ON
)

option(
    VOID_VAULT_ENABLE_SANITIZERS
    "Enable AddressSanitizer and UndefinedBehaviorSanitizer"
    OFF
)

add_library(void_vault_options INTERFACE)

target_compile_features(
    void_vault_options
    INTERFACE cxx_std_20
)

if(MSVC)
    target_compile_options(void_vault_options INTERFACE 
        /W4
        /permissive-
        /sdl
        /GS
    )
else()
    target_compile_options(void_vault_options INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wformat=2
    )

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(
            void_vault_options
            INTERFACE 
            -fstack-protector-strong
        )

    endif()
endif()

if(WIN32)
    if(MSVC)
        target_compile_options(
            void_vault_options
            INTERFACE /guard:cf
        )
        target_link_options(
            void_vault_options
            INTERFACE /guard:cf
        )

    endif()

elseif(UNIX AND NOT APPLE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_link_options(
            void_vault_options
            INTERFACE
            -Wl,-z,relro,-z,now
        )
    endif()
endif()

if(VOID_VAULT_ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"
       AND NOT WIN32)
        target_compile_options(
            void_vault_options
            INTERFACE 
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        )

        target_link_options(
            void_vault_options
            INTERFACE 
            -fsanitize=address,undefined
        )
    
    else()
        message(FATAL_ERROR
            "Requested sanitizer configuration is not "
            "supported by this compiler/platform setup."
        )
    endif()
endif()

option(
    VOID_VAULT_STATIC_RUNTIME
    "MinGW: link libstdc++/libsodium/winpthread statically so foreign DLLs on PATH (e.g. Anaconda) cannot shadow them"
    ON
)

if(MINGW AND VOID_VAULT_STATIC_RUNTIME)
    target_link_options(void_vault_options INTERFACE -static)
    target_compile_definitions(void_vault_options INTERFACE SODIUM_STATIC)
    set(VOID_VAULT_SODIUM_LIBS ${SODIUM_STATIC_LIBRARIES})
    target_link_directories(void_vault_options INTERFACE ${SODIUM_STATIC_LIBRARY_DIRS})
else()
    set(VOID_VAULT_SODIUM_LIBS PkgConfig::SODIUM)
endif()

# Shared security/storage core used by the application and every test.
add_library(void_vault_core STATIC
    src/vault/vault.cpp
    src/vault/broker.cpp
    src/vault/void_vault_c.cpp
    src/security/audit_log.cpp
    src/security/auth.cpp
    src/security/encryption.cpp
    src/storage/storage.cpp
)

target_include_directories(
    void_vault_core
    PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src"
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(
    void_vault_core
    PUBLIC
    void_vault_options
    ${VOID_VAULT_SODIUM_LIBS}
)

add_library(void_vault_shared SHARED
    src/vault/vault.cpp
    src/vault/broker.cpp
    src/vault/void_vault_c.cpp
    src/security/audit_log.cpp
    src/security/auth.cpp
    src/security/encryption.cpp
    src/storage/storage.cpp
)
target_compile_definitions(void_vault_shared PRIVATE VOID_VAULT_BUILD_SHARED)
target_include_directories(
    void_vault_shared
    PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src"
    ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(
    void_vault_shared
    PRIVATE
    void_vault_options
    ${VOID_VAULT_SODIUM_LIBS}
)
set_target_properties(void_vault_shared PROPERTIES
    OUTPUT_NAME "void_vault"
    PREFIX ""
)

add_executable(void_vault src/main.cpp)
target_link_libraries(void_vault PRIVATE void_vault_core)
if(VOID_VAULT_BUILD_TESTS)
    enable_testing()

    if(EXISTS "${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt")
        add_subdirectory(tests)
    else()
        message(STATUS
            "Test targets deferred: tests/CMakeLists.txt "
            "has not been created yet."
        )
    endif()
endif()