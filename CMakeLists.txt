cmake_minimum_required(VERSION 3.5.0)
project(ntoseye VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_STANDARD 23)

find_package(sol2)
find_package(Zydis)

configure_file(version.h.in version.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

file(GLOB GLOBBED_SOURCES CONFIGURE_DEPENDS "ntoseye/*.cpp")

add_executable(ntoseye ${GLOBBED_SOURCES})
target_link_libraries(ntoseye tbb readline Zydis lua dl m curl LLVM lldb)