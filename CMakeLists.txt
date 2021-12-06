cmake_minimum_required(VERSION 3.10)

project(cwire LANGUAGES C VERSION 0.1.0)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Build Options
option(BUILD_SHARED_LIBS "Build shared libraries (rather than static ones)" ON)

add_library(cwire
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/b64.c
    # DNS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dns.c
    # llhttp
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/src/api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/src/http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/src/llhttp.c
    # URL
    ${CMAKE_CURRENT_SOURCE_DIR}/src/url.c
    # SOCKET
    ${CMAKE_CURRENT_SOURCE_DIR}/src/socket.c
    # TLS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/bio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/context.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tls.c
    # WEBSOCKET
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws.c
    # HTTP
    ${CMAKE_CURRENT_SOURCE_DIR}/src/http.c
)

set_target_properties(cwire PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

find_package(OpenSSL REQUIRED)
add_subdirectory(deps/libuv)

target_include_directories(cwire PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include 
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(cwire PUBLIC
    # TLS
    OpenSSL::SSL 
    OpenSSL::Crypto 
    # Event Loop
    uv_a
)

target_compile_options(cwire PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall>
)

# DEMO

add_executable(cwire-demo
    src/demo.c
)

target_link_libraries(cwire-demo cwire)
