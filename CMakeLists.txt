cmake_minimum_required(VERSION 3.9)
project(meshcore-sniffer C)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})

# Homebrew include/link paths on MacOS (Intel and Apple Silicon)
if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
        link_directories(/opt/homebrew/lib)
        include_directories(/opt/homebrew/include)
    else()
        link_directories(/usr/local/lib)
        include_directories(/usr/local/include)
    endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common -Wall -Wextra -Wno-unused-parameter -std=c99 -Werror=implicit-function-declaration")
if(NOT DEFINED MESH_SAN)
    set(MESH_SAN "address")
endif()
# Debug build picks a sanitizer via -DMESH_SAN={address,thread,undefined}.
# Default 'address' matches the historical behavior. Use 'thread' for TSAN
# (and disable LTO with -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF; TSAN
# also needs ASLR off at runtime: 'setarch -R').
if(MESH_SAN STREQUAL "thread")
    set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -g3 -O1 -fsanitize=thread -fno-omit-frame-pointer")
else()
    set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -g3 -O0 -fsanitize=${MESH_SAN}")
endif()
set(CMAKE_C_FLAGS_MINSIZEREL "-Os")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -march=native -ggdb3 -g3")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=${MESH_SAN}")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the type of build: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif()

# Required dependencies
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# FFTW3 (single-precision) for LoRa dechirp + spectrum FFT
find_library(FFTW3F_LIB fftw3f)
find_library(FFTW3F_THREADS_LIB fftw3f_threads)
find_path(FFTW3_INC fftw3.h)
if(NOT (FFTW3F_LIB AND FFTW3_INC))
    message(FATAL_ERROR "FFTW3 (float) not found. Install libfftw3-dev.")
endif()
include_directories(${FFTW3_INC})

# OpenSSL for AES-CTR (Meshtastic encrypts payloads with AES-128/256-CTR)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Optional SDR backends -- enable any/all that are installed.
find_package(SoapySDR)
find_package(SDRplay)
find_package(RTLSDR)
find_library(HACKRF_LIB hackrf)
find_path(HACKRF_INC libhackrf/hackrf.h)
if(HACKRF_LIB AND HACKRF_INC)
    set(HACKRF_FOUND TRUE)
endif()
find_library(BLADERF_LIB bladeRF)
find_path(BLADERF_INC libbladeRF.h)
if(BLADERF_LIB AND BLADERF_INC)
    set(BLADERF_FOUND TRUE)
endif()
find_library(UHD_LIB uhd)
find_path(UHD_INC uhd.h)
if(UHD_LIB AND UHD_INC)
    set(UHD_FOUND TRUE)
endif()
find_library(AIRSPY_LIB airspy)
find_path(AIRSPY_INC libairspy/airspy.h)
if(AIRSPY_LIB AND AIRSPY_INC)
    set(AIRSPY_FOUND TRUE)
endif()

set(HAVE_ANY_SDR FALSE)
foreach(_b SOAPYSDR SDRPLAY RTLSDR HACKRF BLADERF UHD AIRSPY)
    if(${_b}_FOUND)
        set(HAVE_ANY_SDR TRUE)
    endif()
endforeach()
if(NOT HAVE_ANY_SDR)
    message(WARNING "No SDR backend found. Live capture will not be available.\n"
                    "Install at least one: libhackrf-dev libbladerf-dev librtlsdr-dev\n"
                    "                      libsoapysdr-dev libuhd-dev libairspy-dev")
endif()

# Optional MQTT
find_library(MOSQUITTO_LIB mosquitto)
find_path(MOSQUITTO_INC mosquitto.h)
if(MOSQUITTO_LIB AND MOSQUITTO_INC)
    set(MOSQUITTO_FOUND TRUE)
endif()

# Optional SQLite3 persistence sink (--sqlite-db=PATH)
find_library(SQLITE3_LIB sqlite3)
find_path(SQLITE3_INC sqlite3.h)
if(SQLITE3_LIB AND SQLITE3_INC)
    set(SQLITE3_FOUND TRUE)
endif()

# Optional ZMQ
find_library(ZMQ_LIB zmq)
find_path(ZMQ_INC zmq.h)
if(ZMQ_LIB AND ZMQ_INC)
    set(ZMQ_FOUND TRUE)
endif()

# Sources -- add files here as they land. The current set builds a
# skeleton binary that initialises SIMD and prints the protocol tables;
# channelizer / demod / decoder / outputs land in subsequent phases.
include_directories(${PROJECT_SOURCE_DIR})

# Bundled default wordlist for MeshCore hashtag-channel dictionary
# attacks (meshcore_hashtag_dict.c / recover/meshcore-recover.c). MIT
# licensed (Taknok/French-Wordlist, see recover/wordlists/); vendored
# in-tree rather than fetched at build time so the default works
# offline. Path is absolute to the source tree -- see recover/wordlists/
# README for why this only resolves when running from a checkout
# (no install-time deployment of the data file yet).
set(MC_DEFAULT_HASHTAG_WORDLIST "${PROJECT_SOURCE_DIR}/recover/wordlists/french.txt")

# Small hand-curated set of extra candidate names (generic/thematic
# guesses gathered while debugging real captures), always loaded in
# addition to MC_DEFAULT_HASHTAG_WORDLIST above -- see
# recover/wordlists/meshcore-extras.txt.
set(MC_DEFAULT_HASHTAG_EXTRAS "${PROJECT_SOURCE_DIR}/recover/wordlists/meshcore-extras.txt")

set(SOURCES
    ${PROJECT_SOURCE_DIR}/main.c
    ${PROJECT_SOURCE_DIR}/dedup.c
    ${PROJECT_SOURCE_DIR}/options.c
    ${PROJECT_SOURCE_DIR}/meshtastic.c
    ${PROJECT_SOURCE_DIR}/meshcore.c
    ${PROJECT_SOURCE_DIR}/meshcore_packet.c
    ${PROJECT_SOURCE_DIR}/meshcore_decoders.c
    ${PROJECT_SOURCE_DIR}/file_src.c
    ${PROJECT_SOURCE_DIR}/vita49.c
    ${PROJECT_SOURCE_DIR}/channelizer.c
    ${PROJECT_SOURCE_DIR}/iq_ring.c
    ${PROJECT_SOURCE_DIR}/iq_snapshot.c
    ${PROJECT_SOURCE_DIR}/fftw_wisdom.c
    ${PROJECT_SOURCE_DIR}/webhook.c
    ${PROJECT_SOURCE_DIR}/focused.c
    ${PROJECT_SOURCE_DIR}/pfb.c
    ${PROJECT_SOURCE_DIR}/lora.c
    ${PROJECT_SOURCE_DIR}/keyset.c
    ${PROJECT_SOURCE_DIR}/protobuf.c
    ${PROJECT_SOURCE_DIR}/mesh_packet.c
    ${PROJECT_SOURCE_DIR}/mesh_decoders.c
    ${PROJECT_SOURCE_DIR}/jw.c
    ${PROJECT_SOURCE_DIR}/feed_meshcore_json.c
    ${PROJECT_SOURCE_DIR}/feed.c
    ${PROJECT_SOURCE_DIR}/announce.c
    ${PROJECT_SOURCE_DIR}/gpsd.c
    ${PROJECT_SOURCE_DIR}/archive.c
    ${PROJECT_SOURCE_DIR}/db_sqlite.c
    ${PROJECT_SOURCE_DIR}/c2.c
    ${PROJECT_SOURCE_DIR}/c2_dealer.c
    ${PROJECT_SOURCE_DIR}/geofence.c
    ${PROJECT_SOURCE_DIR}/pcap_out.c
    ${PROJECT_SOURCE_DIR}/psk_dict.c
    ${PROJECT_SOURCE_DIR}/meshcore_hashtag_dict.c
    ${PROJECT_SOURCE_DIR}/schema.c
    ${PROJECT_SOURCE_DIR}/scanner.c
    ${PROJECT_SOURCE_DIR}/web.c
    ${PROJECT_SOURCE_DIR}/cot.c
    ${PROJECT_SOURCE_DIR}/node_db.c
    ${PROJECT_SOURCE_DIR}/sigmf.c
    ${PROJECT_SOURCE_DIR}/simd_generic.c
)

# SIMD kernels -- platform-specific, runtime-detected.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|x86|i[3-6]86")
    set_source_files_properties(${PROJECT_SOURCE_DIR}/simd_sse42.c
        PROPERTIES COMPILE_FLAGS "-msse4.2")
    set_source_files_properties(${PROJECT_SOURCE_DIR}/simd_avx2.c
        PROPERTIES COMPILE_FLAGS "-mavx2 -mfma")
    list(APPEND SOURCES
        ${PROJECT_SOURCE_DIR}/simd_sse42.c
        ${PROJECT_SOURCE_DIR}/simd_avx2.c)
    message(STATUS "SIMD: SSE4.2 + AVX2+FMA kernels enabled (runtime-detected)")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
    list(APPEND SOURCES
        ${PROJECT_SOURCE_DIR}/simd_neon.c)
    message(STATUS "SIMD: NEON kernels enabled (AArch64)")
else()
    message(STATUS "SIMD: scalar only (unrecognised platform)")
endif()

add_executable(meshcore-sniffer ${SOURCES})
target_compile_definitions(meshcore-sniffer PRIVATE
    MC_DEFAULT_HASHTAG_WORDLIST="${MC_DEFAULT_HASHTAG_WORDLIST}"
    MC_DEFAULT_HASHTAG_EXTRAS="${MC_DEFAULT_HASHTAG_EXTRAS}")

target_link_libraries(meshcore-sniffer PRIVATE
    Threads::Threads
    ${FFTW3F_LIB}
    ${OPENSSL_CRYPTO_LIBRARY}
    z   # zlib for archive.c gzipped JSONL
    m)

if(FFTW3F_THREADS_LIB)
    target_link_libraries(meshcore-sniffer PRIVATE ${FFTW3F_THREADS_LIB})
endif()

# OpenMP parallelizes the per-band loop in the channelizer batch path.
# Optional: builds without it just degrade to single-thread.
find_package(OpenMP)
if(OpenMP_C_FOUND)
    target_link_libraries(meshcore-sniffer PRIVATE OpenMP::OpenMP_C)
    message(STATUS "OpenMP enabled for parallel channelizer (-fopenmp)")
endif()

# Per-backend conditional compile / link
foreach(_pair  SOAPYSDR:HAVE_SOAPYSDR:soapysdr.c
               SDRPLAY:HAVE_SDRPLAY:sdrplay.c
               RTLSDR:HAVE_RTLSDR:rtlsdr.c
               HACKRF:HAVE_HACKRF:hackrf.c
               BLADERF:HAVE_BLADERF:bladerf.c
               UHD:HAVE_UHD:usrp.c
               AIRSPY:HAVE_AIRSPY:airspy.c)
    string(REPLACE ":" ";" _parts ${_pair})
    list(GET _parts 0 _name)
    list(GET _parts 1 _def)
    list(GET _parts 2 _src)
    if(${_name}_FOUND)
        message(STATUS "${_name}: enabled")
        # Source files for backends are added once they exist on disk.
        if(EXISTS "${PROJECT_SOURCE_DIR}/${_src}")
            target_sources(meshcore-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/${_src})
            target_compile_definitions(meshcore-sniffer PRIVATE ${_def})
            if(_name STREQUAL "SOAPYSDR")
                target_link_libraries(meshcore-sniffer PRIVATE ${SOAPYSDR_LIBRARIES})
                target_include_directories(meshcore-sniffer PRIVATE ${SOAPYSDR_INCLUDE_DIR})
            elseif(_name STREQUAL "SDRPLAY")
                target_link_libraries(meshcore-sniffer PRIVATE ${SDRPLAY_LIBRARIES})
                target_include_directories(meshcore-sniffer PRIVATE ${SDRPLAY_INCLUDE_DIR})
            elseif(_name STREQUAL "RTLSDR")
                target_link_libraries(meshcore-sniffer PRIVATE ${RTLSDR_LIBRARIES})
                target_include_directories(meshcore-sniffer PRIVATE ${RTLSDR_INCLUDE_DIR})
            elseif(_name STREQUAL "HACKRF")
                target_link_libraries(meshcore-sniffer PRIVATE ${HACKRF_LIB})
                target_include_directories(meshcore-sniffer PRIVATE ${HACKRF_INC})
            elseif(_name STREQUAL "BLADERF")
                target_link_libraries(meshcore-sniffer PRIVATE ${BLADERF_LIB})
                target_include_directories(meshcore-sniffer PRIVATE ${BLADERF_INC})
            elseif(_name STREQUAL "UHD")
                target_link_libraries(meshcore-sniffer PRIVATE ${UHD_LIB})
                target_include_directories(meshcore-sniffer PRIVATE ${UHD_INC})
            elseif(_name STREQUAL "AIRSPY")
                target_link_libraries(meshcore-sniffer PRIVATE ${AIRSPY_LIB})
                target_include_directories(meshcore-sniffer PRIVATE ${AIRSPY_INC})
            endif()
        else()
            message(STATUS "  (${_src} not yet present, will be linked when added)")
        endif()
    else()
        message(STATUS "${_name}: not found")
    endif()
endforeach()

target_sources(meshcore-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/mqtt.c)
if(MOSQUITTO_FOUND)
    target_link_libraries(meshcore-sniffer PRIVATE ${MOSQUITTO_LIB})
    target_include_directories(meshcore-sniffer PRIVATE ${MOSQUITTO_INC})
    target_compile_definitions(meshcore-sniffer PRIVATE HAVE_MQTT)
    message(STATUS "MQTT: enabled")
else()
    message(STATUS "MQTT: not found (mqtt.c stubs out; --mqtt will be a no-op)")
endif()

if(SQLITE3_FOUND)
    target_link_libraries(meshcore-sniffer PRIVATE ${SQLITE3_LIB})
    target_include_directories(meshcore-sniffer PRIVATE ${SQLITE3_INC})
    target_compile_definitions(meshcore-sniffer PRIVATE HAVE_SQLITE3)
    message(STATUS "SQLite3: enabled")
else()
    message(STATUS "SQLite3: not found (db_sqlite.c stubs out; --sqlite-db will be a no-op)")
endif()

target_sources(meshcore-sniffer PRIVATE ${PROJECT_SOURCE_DIR}/zmq_pub.c)
if(ZMQ_FOUND)
    target_link_libraries(meshcore-sniffer PRIVATE ${ZMQ_LIB})
    target_include_directories(meshcore-sniffer PRIVATE ${ZMQ_INC})
    target_compile_definitions(meshcore-sniffer PRIVATE HAVE_ZMQ)
    message(STATUS "ZMQ: enabled")
else()
    message(STATUS "ZMQ: not found (zmq_pub.c stubs out; --zmq will be a no-op)")
endif()

# Webhook sink (--webhook-url=...). Uses libcurl for HTTP/HTTPS POST.
# libcurl is standard on every distro we target and the existing
# package landscape (apt install libcurl4-gnutls-dev or -openssl-dev).
find_package(CURL REQUIRED)
target_link_libraries(meshcore-sniffer PRIVATE CURL::libcurl)
message(STATUS "CURL: enabled for webhooks (${CURL_VERSION_STRING})")

set_property(TARGET meshcore-sniffer PROPERTY C_STANDARD 99)
set_property(TARGET meshcore-sniffer PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

install(TARGETS meshcore-sniffer DESTINATION bin)

# meshtastic-recover: offline PSK recovery from a captured pcap.
# Reuses keyset / mesh_packet / meshtastic / protobuf from the parent.
add_executable(meshtastic-recover
    ${PROJECT_SOURCE_DIR}/recover/meshtastic-recover.c
    ${PROJECT_SOURCE_DIR}/recover/stubs.c
    ${PROJECT_SOURCE_DIR}/keyset.c
    ${PROJECT_SOURCE_DIR}/mesh_packet.c
    ${PROJECT_SOURCE_DIR}/mesh_decoders.c
    ${PROJECT_SOURCE_DIR}/meshtastic.c
    ${PROJECT_SOURCE_DIR}/protobuf.c)
target_link_libraries(meshtastic-recover PRIVATE
    Threads::Threads
    ${OPENSSL_CRYPTO_LIBRARY})
if(OpenMP_C_FOUND)
    target_link_libraries(meshtastic-recover PRIVATE OpenMP::OpenMP_C)
endif()
set_property(TARGET meshtastic-recover PROPERTY C_STANDARD 99)
install(TARGETS meshtastic-recover DESTINATION bin)

# meshcore-recover: offline hashtag-channel name recovery for a single
# captured MeshCore GRP_TXT/GRP_DATA frame. Reuses meshcore.c's own
# hashtag-secret derivation + meshcore_decoders.c's verify/decrypt, so
# it can never drift from what a real node accepts.
add_executable(meshcore-recover
    ${PROJECT_SOURCE_DIR}/recover/meshcore-recover.c
    ${PROJECT_SOURCE_DIR}/meshcore.c
    ${PROJECT_SOURCE_DIR}/meshcore_packet.c
    ${PROJECT_SOURCE_DIR}/meshcore_decoders.c
    ${PROJECT_SOURCE_DIR}/meshcore_hashtag_dict_stub.c)
target_link_libraries(meshcore-recover PRIVATE
    Threads::Threads
    ${OPENSSL_CRYPTO_LIBRARY})
target_compile_definitions(meshcore-recover PRIVATE
    MC_DEFAULT_HASHTAG_WORDLIST="${MC_DEFAULT_HASHTAG_WORDLIST}"
    MC_DEFAULT_HASHTAG_EXTRAS="${MC_DEFAULT_HASHTAG_EXTRAS}")
set_property(TARGET meshcore-recover PROPERTY C_STANDARD 99)
install(TARGETS meshcore-recover DESTINATION bin)

# test_oversample_self: diagnostic-only standalone harness that bypasses
# the polyphase channelizer, DDCs one slot at os_factor * BW, and feeds
# the result to lora_decoder_create_os() at the same os_factor. Used to
# A/B-test the "PFB critical sampling loses payload integrity" theory
# against the same /tmp/lf.cs8 capture the live pipeline uses.
add_executable(test_oversample_self
    ${PROJECT_SOURCE_DIR}/tests/test_oversample_self.c
    ${PROJECT_SOURCE_DIR}/lora.c)
target_link_libraries(test_oversample_self PRIVATE
    Threads::Threads
    ${FFTW3F_LIB}
    m)
set_property(TARGET test_oversample_self PROPERTY C_STANDARD 99)

# test_crc_bruteforce: regression test for lora_crc_bruteforce_correct()
# (single-bit CRC16 recovery on CRC-fail LoRa frames). Pure logic test
# against constructed byte vectors, but links lora.c whole (like
# test_oversample_self above) since the function lives in that file.
add_executable(test_crc_bruteforce
    ${PROJECT_SOURCE_DIR}/tests/test_crc_bruteforce.c
    ${PROJECT_SOURCE_DIR}/lora.c)
target_link_libraries(test_crc_bruteforce PRIVATE
    Threads::Threads
    ${FFTW3F_LIB}
    m)
set_property(TARGET test_crc_bruteforce PROPERTY C_STANDARD 99)

# test_pfb_bin_power: feed a wideband cs8 file through the same
# channelizer the live pipeline uses, dump per-bin RMS power in
# dB-relative-to-peak. Used to distinguish "PFB indexing bug"
# vs "FIR sidelobes working as designed" vs "filter rejection
# insufficient for strong-signal cases".
add_executable(test_pfb_bin_power
    ${PROJECT_SOURCE_DIR}/tests/test_pfb_bin_power.c
    ${PROJECT_SOURCE_DIR}/channelizer.c
    ${PROJECT_SOURCE_DIR}/pfb.c)
target_link_libraries(test_pfb_bin_power PRIVATE
    Threads::Threads
    ${FFTW3F_LIB}
    m)
if(OpenMP_C_FOUND)
    target_link_libraries(test_pfb_bin_power PRIVATE OpenMP::OpenMP_C)
endif()
set_property(TARGET test_pfb_bin_power PROPERTY C_STANDARD 99)

# test_iq_ring: unit test for the raw-IQ ring buffer used by Phase 3
# scan-then-focus. Covers linear append, wrap, age-out and the float
# format round-trip; pure CPU, no FFTW.
add_executable(test_iq_ring
    ${PROJECT_SOURCE_DIR}/tests/test_iq_ring.c
    ${PROJECT_SOURCE_DIR}/iq_ring.c)
target_link_libraries(test_iq_ring PRIVATE Threads::Threads)
set_property(TARGET test_iq_ring PROPERTY C_STANDARD 99)

# test_position_decode: regression test for the meshtastic.Position
# protobuf decoder. Hand-encoded fixture exercises sfixed32 lat/lon,
# fixed32 time, sint32 altitude_hae, and the uint32 fields whose field
# numbers were previously shifted (HDOP vs sats_in_view, etc).
add_executable(test_position_decode
    ${PROJECT_SOURCE_DIR}/tests/test_position_decode.c
    ${PROJECT_SOURCE_DIR}/mesh_decoders.c
    ${PROJECT_SOURCE_DIR}/protobuf.c)
target_link_libraries(test_position_decode PRIVATE m)
set_property(TARGET test_position_decode PROPERTY C_STANDARD 99)

# test_mesh_decoders: regression tests for the recent upstream-alignment
# decoder sweep -- NeighborInfo last_rx_time fixed32, ATAK MemberRole
# table, StoreAndForward rr labels, Telemetry LocalStats dispatch,
# PowerMetrics ch8, ATAK GeoChat receipt fields.
add_executable(test_mesh_decoders
    ${PROJECT_SOURCE_DIR}/tests/test_mesh_decoders.c
    ${PROJECT_SOURCE_DIR}/mesh_decoders.c
    ${PROJECT_SOURCE_DIR}/protobuf.c)
target_link_libraries(test_mesh_decoders PRIVATE m)
set_property(TARGET test_mesh_decoders PROPERTY C_STANDARD 99)

# test_meshcore: smoke test for the MeshCore protocol path -- ADVERT
# parsing (in the clear) and GRP_TXT AES-128-ECB+HMAC verify/decrypt.
add_executable(test_meshcore
    ${PROJECT_SOURCE_DIR}/tests/test_meshcore.c
    ${PROJECT_SOURCE_DIR}/meshcore.c
    ${PROJECT_SOURCE_DIR}/meshcore_packet.c
    ${PROJECT_SOURCE_DIR}/meshcore_decoders.c
    ${PROJECT_SOURCE_DIR}/meshcore_hashtag_dict_stub.c)
target_link_libraries(test_meshcore PRIVATE
    Threads::Threads
    ${OPENSSL_CRYPTO_LIBRARY})
set_property(TARGET test_meshcore PROPERTY C_STANDARD 99)

# test_meshcore_hashtag_dict: regression test for the background
# hashtag-channel dictionary attack (meshcore_hashtag_dict.c) -- links
# the real module (not the stub), so it supplies its own
# app_get_meshcore_channels()/web_publish_line()/webhook_publish() the
# way the main sniffer binary normally would.
add_executable(test_meshcore_hashtag_dict
    ${PROJECT_SOURCE_DIR}/tests/test_meshcore_hashtag_dict.c
    ${PROJECT_SOURCE_DIR}/meshcore.c
    ${PROJECT_SOURCE_DIR}/meshcore_packet.c
    ${PROJECT_SOURCE_DIR}/meshcore_decoders.c
    ${PROJECT_SOURCE_DIR}/meshcore_hashtag_dict.c)
target_link_libraries(test_meshcore_hashtag_dict PRIVATE
    Threads::Threads
    ${OPENSSL_CRYPTO_LIBRARY})
set_property(TARGET test_meshcore_hashtag_dict PROPERTY C_STANDARD 99)

# test_feed_meshcore: regression test for the MeshCore JSON
# serializer (feed_meshcore_json.c, split out of feed.c precisely so
# it's linkable/testable without mqtt/zmq/cot/gpsd/geofence/options).
# Covers: GRP_TXT "text" field visibility, and the generic "from" /
# node_db wiring that the web dashboard's JS requires (`if (!p.from)
# return;`) for MeshCore ADVERT/GRP_TXT events to show up at all.
add_executable(test_feed_meshcore
    ${PROJECT_SOURCE_DIR}/tests/test_feed_meshcore.c
    ${PROJECT_SOURCE_DIR}/jw.c
    ${PROJECT_SOURCE_DIR}/feed_meshcore_json.c
    ${PROJECT_SOURCE_DIR}/node_db.c
    ${PROJECT_SOURCE_DIR}/node_db_persist_stub.c
    ${PROJECT_SOURCE_DIR}/meshcore.c
    ${PROJECT_SOURCE_DIR}/meshcore_packet.c
    ${PROJECT_SOURCE_DIR}/meshcore_decoders.c
    ${PROJECT_SOURCE_DIR}/meshcore_hashtag_dict_stub.c)
target_link_libraries(test_feed_meshcore PRIVATE
    Threads::Threads
    ${OPENSSL_CRYPTO_LIBRARY})
set_property(TARGET test_feed_meshcore PROPERTY C_STANDARD 99)

# test_db_sqlite: regression test for db_sqlite.c (the SQLite
# persistence sink). Only built when libsqlite3 was found -- without
# it db_sqlite.c compiles to a no-op stub and there's nothing to
# verify against a real DB file.
if(SQLITE3_FOUND)
    add_executable(test_db_sqlite
        ${PROJECT_SOURCE_DIR}/tests/test_db_sqlite.c
        ${PROJECT_SOURCE_DIR}/db_sqlite.c
        ${PROJECT_SOURCE_DIR}/node_db.c
        ${PROJECT_SOURCE_DIR}/meshtastic.c
        ${PROJECT_SOURCE_DIR}/protobuf.c)
    target_link_libraries(test_db_sqlite PRIVATE
        Threads::Threads
        ${SQLITE3_LIB})
    target_include_directories(test_db_sqlite PRIVATE ${SQLITE3_INC})
    target_compile_definitions(test_db_sqlite PRIVATE HAVE_SQLITE3)
    set_property(TARGET test_db_sqlite PROPERTY C_STANDARD 99)
endif()

# focused_demo: scan-then-focus Phase 2 prototype. One shared file reader
# streams cs8 IQ into N independent focused-decode workers, each with its
# own DDC chain (mixer + LPF + decim) and lora_decoder_t. Bypasses the
# wideband PFB entirely. Architectural primitive for live "stare mode".
add_executable(focused_demo
    ${PROJECT_SOURCE_DIR}/tests/focused_demo.c
    ${PROJECT_SOURCE_DIR}/lora.c)
target_link_libraries(focused_demo PRIVATE
    Threads::Threads
    ${FFTW3F_LIB}
    m)
set_property(TARGET focused_demo PROPERTY C_STANDARD 99)

# CPack
set(CPACK_PACKAGE_NAME "meshcore-sniffer")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Wideband Meshtastic LoRa receiver")
set(CPACK_PACKAGE_VENDOR "CEMAXECUTER LLC")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_GENERATOR "DEB;TGZ")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "CEMAXECUTER LLC")
set(CPACK_DEBIAN_PACKAGE_SECTION "hamradio")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
include(CPack)
