cmake_minimum_required(VERSION 3.5)
project(websocket VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-implicit-function-declaration")

set(CMAKE_CONFIGURATION_TYPES "debug;release" CACHE STRING "Configurations" FORCE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include
	${CMAKE_CURRENT_SOURCE_DIR}/websocket/include
)

set(MBEDTLS
	websocket/library/mbedtls/aes.c
    websocket/library/mbedtls/aesni.c
    websocket/library/mbedtls/aria.c
    websocket/library/mbedtls/asn1parse.c
    websocket/library/mbedtls/asn1write.c
    websocket/library/mbedtls/base64.c
    websocket/library/mbedtls/bignum.c
    websocket/library/mbedtls/camellia.c
    websocket/library/mbedtls/ccm.c
    websocket/library/mbedtls/chacha20.c
    websocket/library/mbedtls/chachapoly.c
    websocket/library/mbedtls/cipher.c
    websocket/library/mbedtls/cipher_wrap.c
    websocket/library/mbedtls/cmac.c
    websocket/library/mbedtls/constant_time.c
    websocket/library/mbedtls/ctr_drbg.c
    websocket/library/mbedtls/debug.c
    websocket/library/mbedtls/des.c
    websocket/library/mbedtls/dhm.c
    websocket/library/mbedtls/ecdh.c
    websocket/library/mbedtls/ecdsa.c
    websocket/library/mbedtls/ecjpake.c
    websocket/library/mbedtls/ecp.c
    websocket/library/mbedtls/ecp_curves.c
    websocket/library/mbedtls/entropy.c
    websocket/library/mbedtls/entropy_poll.c
    websocket/library/mbedtls/error.c
    websocket/library/mbedtls/gcm.c
    websocket/library/mbedtls/hkdf.c
    websocket/library/mbedtls/hmac_drbg.c
    websocket/library/mbedtls/md.c
    websocket/library/mbedtls/md5.c
    websocket/library/mbedtls/memory_buffer_alloc.c
    websocket/library/mbedtls/mps_reader.c
    websocket/library/mbedtls/mps_trace.c
    websocket/library/mbedtls/net_sockets.c
    websocket/library/mbedtls/nist_kw.c
    websocket/library/mbedtls/oid.c
    websocket/library/mbedtls/padlock.c
    websocket/library/mbedtls/pem.c
    websocket/library/mbedtls/pk.c
    websocket/library/mbedtls/pkcs12.c
    websocket/library/mbedtls/pkcs5.c
    websocket/library/mbedtls/pkparse.c
    websocket/library/mbedtls/pkwrite.c
    websocket/library/mbedtls/pk_wrap.c
    websocket/library/mbedtls/platform.c
    websocket/library/mbedtls/platform_util.c
    websocket/library/mbedtls/poly1305.c
    websocket/library/mbedtls/psa_crypto.c
    websocket/library/mbedtls/psa_crypto_aead.c
    websocket/library/mbedtls/psa_crypto_cipher.c
    websocket/library/mbedtls/psa_crypto_client.c
    websocket/library/mbedtls/psa_crypto_driver_wrappers.c
    websocket/library/mbedtls/psa_crypto_ecp.c
    websocket/library/mbedtls/psa_crypto_hash.c
    websocket/library/mbedtls/psa_crypto_mac.c
    websocket/library/mbedtls/psa_crypto_rsa.c
    websocket/library/mbedtls/psa_crypto_se.c
    websocket/library/mbedtls/psa_crypto_slot_management.c
    websocket/library/mbedtls/psa_crypto_storage.c
    websocket/library/mbedtls/psa_its_file.c
    websocket/library/mbedtls/ripemd160.c
    websocket/library/mbedtls/rsa.c
    websocket/library/mbedtls/rsa_alt_helpers.c
    websocket/library/mbedtls/sha1.c
    websocket/library/mbedtls/sha256.c
    websocket/library/mbedtls/sha512.c
    websocket/library/mbedtls/ssl_cache.c
    websocket/library/mbedtls/ssl_ciphersuites.c
    websocket/library/mbedtls/ssl_cli.c
    websocket/library/mbedtls/ssl_cookie.c
    websocket/library/mbedtls/ssl_debug_helpers_generated.c
    websocket/library/mbedtls/ssl_msg.c
    websocket/library/mbedtls/ssl_srv.c
    websocket/library/mbedtls/ssl_ticket.c
    websocket/library/mbedtls/ssl_tls.c
    websocket/library/mbedtls/ssl_tls13_client.c
    websocket/library/mbedtls/ssl_tls13_generic.c
    websocket/library/mbedtls/ssl_tls13_keys.c
    websocket/library/mbedtls/ssl_tls13_server.c
    websocket/library/mbedtls/threading.c
    websocket/library/mbedtls/timing.c
    websocket/library/mbedtls/version.c
    websocket/library/mbedtls/version_features.c
    websocket/library/mbedtls/x509.c
    websocket/library/mbedtls/x509write_crt.c
    websocket/library/mbedtls/x509write_csr.c
    websocket/library/mbedtls/x509_create.c
    websocket/library/mbedtls/x509_crl.c
    websocket/library/mbedtls/x509_crt.c
    websocket/library/mbedtls/x509_csr.c
)

set(API
	websocket/library/websocket/websocket_c_api.cpp
)

set(ZLIB
	websocket/library/websocket/gzclose.c
	websocket/library/websocket/gzlib.c
	websocket/library/websocket/gzread.c
	websocket/library/websocket/gzwrite.c
	websocket/library/websocket/adler32.c
	websocket/library/websocket/crc32.c
	websocket/library/websocket/trees.c
	websocket/library/websocket/inftrees.c
	websocket/library/websocket/inffast.c
	websocket/library/websocket/zutil.c
	websocket/library/websocket/deflate.c
	websocket/library/websocket/inflate.c
)

set(CORE
    websocket/library/websocket/flate.cpp
    websocket/library/websocket/byte_stream.cpp
	websocket/library/websocket/endian.cpp
	websocket/library/websocket/http.cpp
	websocket/library/websocket/handshake.cpp
    websocket/library/websocket/frame.cpp
	websocket/library/websocket/websocket.cpp
)

set(SOURCES
    websocket/library/websocket/example.cpp
)

source_group("mbedtls" FILES ${MBEDTLS})
source_group("zlib" FILES ${ZLIB})
source_group("websocket" FILES ${CORE} ${API} ${SOURCES})

option(ENABLE_C_API "enable c api" ON)
option(ENABLE_CPP_API "enable cpp api" ON)
option(BUILD_SHARED "build shared library" OFF)
option(BUILD_STATIC "build static library" OFF)
option(BUILD_EXAMPLE "build example" ON)
option(EXAMPLE_C_API "use c api in example build" OFF)

if(BUILD_SHARED)
	add_library(LIB_SHARED SHARED ${MBEDTLS} ${API} ${ZLIB} ${CORE})
	
	target_compile_definitions(LIB_SHARED PRIVATE WEBSOCKET_SHARED WEBSOCKET_EXPORT)
	
	if(ENABLE_CPP_API)
		target_compile_definitions(LIB_SHARED PRIVATE WEBSOCKET_CPP_API)
	endif()
	
	if(ENABLE_C_API)
		target_compile_definitions(LIB_SHARED PRIVATE WEBSOCKET_C_API)
	endif()
	
	if(WIN32)
		target_link_libraries(LIB_SHARED wsock32 ws2_32)
	endif()
endif()

if(BUILD_STATIC)
	add_library(LIB_STATIC STATIC ${MBEDTLS} ${API} ${ZLIB} ${CORE})

	if(ENABLE_CPP_API)
		target_compile_definitions(LIB_STATIC PRIVATE WEBSOCKET_CPP_API)
	endif()
	
	if(ENABLE_C_API)
		target_compile_definitions(LIB_STATIC PRIVATE WEBSOCKET_C_API)
	endif()
	
	if(WIN32)
		target_link_libraries(LIB_STATIC wsock32 ws2_32)
	endif()
endif()

if(BUILD_EXAMPLE)
	add_executable(EXAMPLE_CLIENT ${MBEDTLS} ${API} ${ZLIB} ${CORE} ${SOURCES})
	
	target_compile_definitions(EXAMPLE_CLIENT PRIVATE WEBSOCKET_EXAMPLE_ENDPOINT_CLIENT)
	
	add_executable(EXAMPLE_SERVER ${MBEDTLS} ${API} ${ZLIB} ${CORE} ${SOURCES})
	
	target_compile_definitions(EXAMPLE_SERVER PRIVATE WEBSOCKET_EXAMPLE_ENDPOINT_SERVER)
	
	if(ENABLE_CPP_API)
		target_compile_definitions(EXAMPLE_CLIENT PRIVATE WEBSOCKET_CPP_API)
		target_compile_definitions(EXAMPLE_SERVER PRIVATE WEBSOCKET_CPP_API)
	endif()
	
	if(ENABLE_C_API)
		target_compile_definitions(EXAMPLE_CLIENT PRIVATE WEBSOCKET_C_API)
		target_compile_definitions(EXAMPLE_SERVER PRIVATE WEBSOCKET_C_API)
	endif()
	
	if(EXAMPLE_C_API)
		target_compile_definitions(EXAMPLE_CLIENT PRIVATE WEBSOCKET_EXAMPLE_C_API)
		target_compile_definitions(EXAMPLE_SERVER PRIVATE WEBSOCKET_EXAMPLE_C_API)
	endif()
	
	if(WIN32)
		target_link_libraries(EXAMPLE_CLIENT wsock32 ws2_32)
		target_link_libraries(EXAMPLE_SERVER wsock32 ws2_32)
	endif()
endif()