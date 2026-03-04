cmake_minimum_required(VERSION 3.5)
project(websocket VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

set(CMAKE_CONFIGURATION_TYPES "debug;release" CACHE STRING "Configurations" FORCE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include
	${CMAKE_CURRENT_SOURCE_DIR}/websocket/include
)

set(MBEDTLS
        websocket/source/mbedtls/aes.c
        websocket/source/mbedtls/aesni.c
        websocket/source/mbedtls/aria.c
        websocket/source/mbedtls/asn1parse.c
        websocket/source/mbedtls/asn1write.c
        websocket/source/mbedtls/base64.c
        websocket/source/mbedtls/bignum.c
        websocket/source/mbedtls/camellia.c
        websocket/source/mbedtls/ccm.c
        websocket/source/mbedtls/chacha20.c
        websocket/source/mbedtls/chachapoly.c
        websocket/source/mbedtls/cipher.c
        websocket/source/mbedtls/cipher_wrap.c
        websocket/source/mbedtls/cmac.c
        websocket/source/mbedtls/constant_time.c
        websocket/source/mbedtls/ctr_drbg.c
        websocket/source/mbedtls/debug.c
        websocket/source/mbedtls/des.c
        websocket/source/mbedtls/dhm.c
        websocket/source/mbedtls/ecdh.c
        websocket/source/mbedtls/ecdsa.c
        websocket/source/mbedtls/ecjpake.c
        websocket/source/mbedtls/ecp.c
        websocket/source/mbedtls/ecp_curves.c
        websocket/source/mbedtls/entropy.c
        websocket/source/mbedtls/entropy_poll.c
        websocket/source/mbedtls/error.c
        websocket/source/mbedtls/gcm.c
        websocket/source/mbedtls/hkdf.c
        websocket/source/mbedtls/hmac_drbg.c
        websocket/source/mbedtls/md.c
        websocket/source/mbedtls/md5.c
        websocket/source/mbedtls/memory_buffer_alloc.c
        websocket/source/mbedtls/mps_reader.c
        websocket/source/mbedtls/mps_trace.c
        websocket/source/mbedtls/net_sockets.c
        websocket/source/mbedtls/nist_kw.c
        websocket/source/mbedtls/oid.c
        websocket/source/mbedtls/padlock.c
        websocket/source/mbedtls/pem.c
        websocket/source/mbedtls/pk.c
        websocket/source/mbedtls/pkcs12.c
        websocket/source/mbedtls/pkcs5.c
        websocket/source/mbedtls/pkparse.c
        websocket/source/mbedtls/pkwrite.c
        websocket/source/mbedtls/pk_wrap.c
        websocket/source/mbedtls/platform.c
        websocket/source/mbedtls/platform_util.c
        websocket/source/mbedtls/poly1305.c
        websocket/source/mbedtls/psa_crypto.c
        websocket/source/mbedtls/psa_crypto_aead.c
        websocket/source/mbedtls/psa_crypto_cipher.c
        websocket/source/mbedtls/psa_crypto_client.c
        websocket/source/mbedtls/psa_crypto_driver_wrappers.c
        websocket/source/mbedtls/psa_crypto_ecp.c
        websocket/source/mbedtls/psa_crypto_hash.c
        websocket/source/mbedtls/psa_crypto_mac.c
        websocket/source/mbedtls/psa_crypto_rsa.c
        websocket/source/mbedtls/psa_crypto_se.c
        websocket/source/mbedtls/psa_crypto_slot_management.c
        websocket/source/mbedtls/psa_crypto_storage.c
        websocket/source/mbedtls/psa_its_file.c
        websocket/source/mbedtls/ripemd160.c
        websocket/source/mbedtls/rsa.c
        websocket/source/mbedtls/rsa_alt_helpers.c
        websocket/source/mbedtls/sha1.c
        websocket/source/mbedtls/sha256.c
        websocket/source/mbedtls/sha512.c
        websocket/source/mbedtls/ssl_cache.c
        websocket/source/mbedtls/ssl_ciphersuites.c
        websocket/source/mbedtls/ssl_cli.c
        websocket/source/mbedtls/ssl_cookie.c
        websocket/source/mbedtls/ssl_debug_helpers_generated.c
        websocket/source/mbedtls/ssl_msg.c
        websocket/source/mbedtls/ssl_srv.c
        websocket/source/mbedtls/ssl_ticket.c
        websocket/source/mbedtls/ssl_tls.c
        websocket/source/mbedtls/ssl_tls13_client.c
        websocket/source/mbedtls/ssl_tls13_generic.c
        websocket/source/mbedtls/ssl_tls13_keys.c
        websocket/source/mbedtls/ssl_tls13_server.c
        websocket/source/mbedtls/threading.c
        websocket/source/mbedtls/timing.c
        websocket/source/mbedtls/version.c
        websocket/source/mbedtls/version_features.c
        websocket/source/mbedtls/x509.c
        websocket/source/mbedtls/x509write_crt.c
        websocket/source/mbedtls/x509write_csr.c
        websocket/source/mbedtls/x509_create.c
        websocket/source/mbedtls/x509_crl.c
        websocket/source/mbedtls/x509_crt.c
        websocket/source/mbedtls/x509_csr.c
)

set(API
        websocket/source/websocket/websocket_c_api.cpp
)

set(ZLIB
        websocket/source/websocket/gzclose.c
        websocket/source/websocket/gzlib.c
        websocket/source/websocket/gzread.c
        websocket/source/websocket/gzwrite.c
        websocket/source/websocket/adler32.c
        websocket/source/websocket/crc32.c
        websocket/source/websocket/trees.c
        websocket/source/websocket/inftrees.c
        websocket/source/websocket/inffast.c
        websocket/source/websocket/zutil.c
        websocket/source/websocket/deflate.c
        websocket/source/websocket/inflate.c
)

set(CORE
        websocket/source/websocket/flate.cpp
        websocket/source/websocket/byte_stream.cpp
        websocket/source/websocket/endian.cpp
        websocket/source/websocket/http.cpp
        websocket/source/websocket/handshake.cpp
        websocket/source/websocket/frame.cpp
        websocket/source/websocket/websocket.cpp
)

set(SOURCES
        websocket/source/websocket/example.cpp
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