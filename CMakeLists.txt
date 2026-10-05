cmake_minimum_required(VERSION 3.16)
project(AttendantForge VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(attendantforge_core src/attendantforge.c)
target_include_directories(attendantforge_core PUBLIC include)

add_executable(attendantforge src/main.c)
target_link_libraries(attendantforge PRIVATE attendantforge_core)

include(CTest)
if(BUILD_TESTING)
    add_executable(attendantforge_tests tests/test_main.c)
    target_link_libraries(attendantforge_tests PRIVATE attendantforge_core)
    add_test(NAME attendantforge_tests COMMAND attendantforge_tests)
endif()
