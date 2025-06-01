cmake_minimum_required(VERSION 3.15)

project(SKDP_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# SKDP Static Library
file(GLOB_RECURSE SKDP_SOURCES "Source/SKDP/*.c")
file(GLOB_RECURSE SKDP_HEADERS "Source/SKDP/include/*.h")

add_library(skdp STATIC ${SKDP_SOURCES} ${SKDP_HEADERS})
target_include_directories(skdp PUBLIC Source/SKDP)
target_link_libraries(skdp PUBLIC qsc)

# SKDP Client
file(GLOB_RECURSE SKDP_CLIENT_SOURCES "Source/Client/*.c")

add_executable(skdp_client ${SKDP_CLIENT_SOURCES})
target_include_directories(skdp_client PRIVATE "Source/Client")
target_link_libraries(skdp_client PRIVATE skdp)

# SKDP Server
file(GLOB_RECURSE SKDP_SERVER_SOURCES "Source/Server/*.c")

add_executable(skdp_server ${SKDP_SERVER_SOURCES})
target_include_directories(skdp_server PRIVATE Source/Server)
target_link_libraries(skdp_server PRIVATE skdp)

# Warnings
foreach(target skdp skdp_client skdp_server)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
