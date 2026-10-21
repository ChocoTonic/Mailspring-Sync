cmake_minimum_required(VERSION 3.16)
project(mailcore_certificate_key_tests LANGUAGES CXX)
enable_testing()
add_executable(certificate-key-tests certificate-key-tests.cpp)
target_compile_features(certificate-key-tests PRIVATE cxx_std_11)
find_package(OpenSSL REQUIRED)
target_link_libraries(certificate-key-tests PRIVATE OpenSSL::Crypto)
add_test(NAME certificate-key-blocklist
    COMMAND certificate-key-tests "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

find_package(CURL 7.80 REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_executable(platform-certificate-tests platform-certificate-tests.cpp)
add_executable(curl-security-client curl-security-client.cpp)
add_executable(curl-security-client-denied curl-security-client.cpp)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/curl-blocked.spki-sha256" testBlockedKey)
string(STRIP "${testBlockedKey}" testBlockedKey)
target_compile_definitions(curl-security-client-denied PRIVATE MAILCORE_TEST_BLOCKED_SPKI="${testBlockedKey}")
foreach(target platform-certificate-tests curl-security-client curl-security-client-denied)
    target_compile_features(${target} PRIVATE cxx_std_11)
    target_link_libraries(${target} PRIVATE CURL::libcurl OpenSSL::SSL OpenSSL::Crypto)
    if(APPLE)
        target_link_libraries(${target} PRIVATE "-framework Security" "-framework CoreFoundation")
    elseif(WIN32)
        target_link_libraries(${target} PRIVATE secur32 crypt32)
    endif()
endforeach()
add_test(NAME platform-certificate-policy
    COMMAND platform-certificate-tests "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
add_test(NAME curl-precredential-key-policy
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/curl-loopback-tests.py"
            "$<TARGET_FILE:curl-security-client>" "$<TARGET_FILE:curl-security-client-denied>"
            "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
set_tests_properties(curl-precredential-key-policy PROPERTIES TIMEOUT 180)
