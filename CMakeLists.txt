cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(rocket LANGUAGES C CXX VERSION 0.0.1)


#find threads
find_package(Threads REQUIRED)

#check if epoll and eventfd exist
include(CheckIncludeFiles)
check_include_files(sys/eventfd.h HAS_EVENTFD)
check_include_files(sys/epoll.h HAS_EPOLL)

if (NOT HAS_EVENTFD)
    message(FATAL_ERROR "Required header sys/eventfd.h not found")
endif ()

if (NOT HAS_EPOLL)
    message(FATAL_ERROR "Required header sys/epoll.h not found")
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR
        CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "-Wall -Wfatal-errors -pedantic -std=c++17")
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")

endif ()

set(CMAKE_BINARY_DIR "bin")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(src)
include_directories(lib)

add_library(loop src/loop.cpp)
add_library(event src/event.cpp)
add_library(http_parser lib/http-parser/http_parser.c)

add_executable(event_test test/event_test.cpp)
target_link_libraries(event_test event loop ${CMAKE_THREAD_LIBS_INIT})

add_executable(echo_test test/echo_test.cpp)
target_link_libraries(echo_test event loop ${CMAKE_THREAD_LIBS_INIT})

add_executable(static_http_server examples/http_server.cpp)
target_link_libraries(static_http_server event http_parser
        loop ${CMAKE_THREAD_LIBS_INIT})
