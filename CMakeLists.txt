cmake_minimum_required(VERSION 3.1)

project(mdns)

set(LIBRARY_FILES mdns.h mdns.c mdnsd.h mdnsd.c)

add_library(tinysvcmdns SHARED ${LIBRARY_FILES})
add_executable(${PROJECT_NAME} testmdnsd.c)

target_link_libraries(${PROJECT_NAME} tinysvcmdns)

if(WIN32)
  target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
else()
  target_link_libraries(${PROJECT_NAME} pthread)
endif()