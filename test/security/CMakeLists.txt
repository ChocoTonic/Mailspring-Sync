cmake_minimum_required(VERSION 3.16)
project(mailcore_certificate_key_tests LANGUAGES CXX)
enable_testing()
add_executable(certificate-key-tests certificate-key-tests.cpp)
target_compile_features(certificate-key-tests PRIVATE cxx_std_11)
find_package(OpenSSL REQUIRED)
target_link_libraries(certificate-key-tests PRIVATE OpenSSL::Crypto)
add_test(NAME certificate-key-blocklist
    COMMAND certificate-key-tests "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
