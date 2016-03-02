cmake_minimum_required(VERSION 3.1)

project(mdns)

file(GLOB_RECURSE LIBRARY_FILES ${CMAKE_CURRENT_LIST_DIR}/*.h ${CMAKE_CURRENT_LIST_DIR}/*.c)
add_executable(${PROJECT_NAME} ${LIBRARY_FILES})
if(WIN32)
  target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
endif()