include_directories(${PROJECT_BINARY_DIR})
include_directories(${PROJECT_SOURCE_DIR})

find_package(Check REQUIRED)


set(LIBS ${CHECK_LIBRARIES} tinysvcmdns pthread)

if(WIN32)
    list(APPEND LIBS wsock32 ws2_32)
endif()

if(CMAKE_COMPILER_IS_GNUCC OR "x${CMAKE_C_COMPILER_ID}" STREQUAL "xClang")
    add_definitions(-Wno-sign-conversion)
endif()

# Valgrind definition
set(UA_TEST_WITH_VALGRIND ON)
SET(VALGRIND_FLAGS --quiet --trace-children=yes --leak-check=full)
macro(add_test_valgrind TEST_NAME)
    IF(UA_TEST_WITH_VALGRIND)
        add_test(${TEST_NAME}
                valgrind --error-exitcode=1 ${VALGRIND_FLAGS} ${ARGN} )
    ELSE()
        add_test(${TEST_NAME} ${ARGN})
    ENDIF()
endmacro()

add_executable(check_service check_service.c)
target_link_libraries(check_service ${LIBS})
add_test_valgrind(builtin ${CMAKE_CURRENT_BINARY_DIR}/check_service)
