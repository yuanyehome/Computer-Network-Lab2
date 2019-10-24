cmake_minimum_required(VERSION 3.14)
project(net_stack)
set(LIB_NAME net_stack)

SET(CMAKE_C_COMPILER /usr/bin/clang)
SET(CMAKE_CXX_COMPILER /usr/bin/clang++)

include_directories(./include)

# Select flags.
# set(CMAKE_CXX_FLAGS "-O0 -g -Wall -fsanitize=address")
set(CMAKE_CXX_FLAGS "-O0 -g -Wall -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -Wall -fsanitize=address")

set(CMAKE_CXX_STANDARD 17)

file(GLOB proj_HEADERS "include/*.h")
file(GLOB proj_SOURCES "src/*.cpp")

# Add core library.
include(FindPCAP.cmake)

find_package(Threads)
add_library(${LIB_NAME} SHARED ${proj_HEADERS} ${proj_SOURCES})
target_link_libraries(net_stack ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})


# Add subdirectories.
add_subdirectory(test_code)
