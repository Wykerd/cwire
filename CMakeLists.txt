cmake_minimum_required(VERSION 3.11)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

project(cwire LANGUAGES C VERSION 0.1.0)

add_library(cwire SHARED
    src/common.c
    src/net.c
    # URL
    src/url.c
    # SOCKET
    src/socket.c
    # TLS
    src/crypto/bio.c
    src/crypto/context.c
    src/tls.c
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
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/build
    
    ${UV_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(cwire 
    # HTTP
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/llhttp/build/libllhttp.a
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
