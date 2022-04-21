cmake_minimum_required(VERSION 3.22)
project(CloudStorageProject)

set(CMAKE_CXX_STANDARD 14)
include_directories(/usr/include/openssl/)
link_libraries(crypto)


add_executable(CloudStorageProject main.cpp)
