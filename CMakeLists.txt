cmake_minimum_required(VERSION 3.1)
project(libhttp_connector C)

find_package(OpenSSL REQUIRED)

add_library(http_connector ${PROJECT_SOURCE_DIR}/src/http_connector.c)
target_link_libraries(http_connector OpenSSL::SSL)
if(MINGW)
  target_link_libraries(http_connector wsock32 ws2_32)
endif(MINGW)

