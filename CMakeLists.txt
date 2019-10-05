cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
project(rocket C CXX)

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

if(CMAKE_CXX_COMPILER_ID MATCHES GNU OR
	CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_CXX_FLAGS "-Wall -Wfatal-errors -pedantic -std=c++17")
	set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3")

endif()

set(CMAKE_BINARY_DIR "bin")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(src)

add_library(loop src/loop.cpp)
add_library(event src/event.cpp)

add_executable(event_test test/event_test.cpp)
target_link_libraries(event_test event loop ${CMAKE_THREAD_LIBS_INIT})

