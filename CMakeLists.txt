cmake_minimum_required(VERSION 2.8)

project(mdns)

if(CMAKE_COMPILER_IS_GNUCC OR "x${CMAKE_C_COMPILER_ID}" STREQUAL "xClang")
  # Compiler
  #add_definitions(
  add_definitions(-std=c99 -pipe -Wall -Wextra -Werror -Wformat -Wno-unused-parameter
          -Wno-unused-function -Wno-unused-label -Wpointer-arith -Wreturn-type -Wsign-compare
          -Wmultichar -Wstrict-overflow -Wcast-qual -Wmissing-prototypes -Wstrict-prototypes
          -Winit-self -Wuninitialized -Wformat-security -Wformat-nonliteral)
  if(NOT WIN32 AND NOT CYGWIN)
    add_definitions(-Wshadow -Wconversion -fvisibility=hidden -fPIC)
  endif()
endif()

# Building shared libs (dll, so)
set(MDNS_DYNAMIC_LINKING OFF)
if(BUILD_SHARED_LIBS)
  set(MDNS_DYNAMIC_LINKING ON)
endif()

configure_file("mdns_config.h.in" "${PROJECT_BINARY_DIR}/mdns_config.h")
include_directories(${PROJECT_BINARY_DIR})

set(LIBRARY_FILES mdns.h mdns.c mdnsd.h mdnsd.c)

add_library(tinysvcmdns SHARED ${LIBRARY_FILES})
if(WIN32)
  target_link_libraries(tinysvcmdns wsock32 ws2_32)
endif()

add_executable(${PROJECT_NAME} testmdnsd.c)

target_link_libraries(${PROJECT_NAME} tinysvcmdns)

if(WIN32)
  target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
else()
  target_link_libraries(${PROJECT_NAME} pthread)
endif()