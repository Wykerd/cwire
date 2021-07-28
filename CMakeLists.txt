cmake_minimum_required(VERSION 3.11)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

project(cwire LANGUAGES C VERSION 0.1.0)

add_library(cwire SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/net.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/b64.c
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
)

set_target_properties(cwire PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)

find_package(OpenSSL REQUIRED)
find_package(UV REQUIRED)
find_package(Threads REQUIRED)

target_include_directories(cwire PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include 
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/include
    
    ${UV_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(cwire 
    # TLS
    OpenSSL::SSL 
    OpenSSL::Crypto 
    # Event Loop
    ${UV_LIBRARIES} 
    # Theads
    Threads::Threads
)

# DEMO

add_executable(cwire-demo
    src/demo.c
)

target_link_libraries(cwire-demo cwire)
