cmake_minimum_required(VERSION 3.1)

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

set(LIBRARY_FILES mdns.h mdns.c mdnsd.h mdnsd.c)

add_library(tinysvcmdns SHARED ${LIBRARY_FILES})
add_executable(${PROJECT_NAME} testmdnsd.c)

target_link_libraries(${PROJECT_NAME} tinysvcmdns)

if(WIN32)
  target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
else()
  target_link_libraries(${PROJECT_NAME} pthread)
endif()