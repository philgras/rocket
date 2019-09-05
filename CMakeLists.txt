cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
project(luna C CXX)

if(CMAKE_CXX_COMPILER_ID MATCHES GNU OR
	CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_CXX_FLAGS "-Wall -Wfatal-errors -pedantic -std=c++17")
	set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3")

endif()

set(CMAKE_BINARY_DIR "bin")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(main src/main.cpp src/loop.cpp)
