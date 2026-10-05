cmake_minimum_required(VERSION 3.16)
project(AttendantForge VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(AF_ENABLE_WARNINGS "Enable strict compiler warnings" ON)

add_library(attendantforge_core
    src/attendantforge.c
    src/zip_analyzer.c
    src/pdf_analyzer.c
    src/policy.c
    src/probe.c
    src/format_analyzer.c
    src/batch.c
)
target_include_directories(attendantforge_core PUBLIC include PRIVATE src)

add_executable(attendantforge src/main.c)
target_link_libraries(attendantforge PRIVATE attendantforge_core)

if(AF_ENABLE_WARNINGS)
    if(MSVC)
        target_compile_options(attendantforge_core PRIVATE /W4)
        target_compile_options(attendantforge PRIVATE /W4)
    else()
        target_compile_options(attendantforge_core PRIVATE -Wall -Wextra -Wpedantic)
        target_compile_options(attendantforge PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS attendantforge RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES config/attendantforge.conf.example config/high-security.conf
        DESTINATION ${CMAKE_INSTALL_DATADIR}/attendantforge/config)
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DATADIR}/attendantforge/docs)
install(FILES README.md LICENSE SECURITY.md DESTINATION ${CMAKE_INSTALL_DATADIR}/attendantforge)

include(CTest)
if(BUILD_TESTING)
    add_executable(attendantforge_tests tests/test_main.c)
    target_link_libraries(attendantforge_tests PRIVATE attendantforge_core)
    target_include_directories(attendantforge_tests PRIVATE src)
    if(AF_ENABLE_WARNINGS)
        if(MSVC)
            target_compile_options(attendantforge_tests PRIVATE /W4)
        else()
            target_compile_options(attendantforge_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    endif()
    add_test(NAME attendantforge_tests COMMAND attendantforge_tests)
endif()
