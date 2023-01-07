cmake_minimum_required(VERSION 3.21)

project(LLWebsocketR)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)

file(GLOB_RECURSE SRC_FILES_DIR
    ${PROJECT_SOURCE_DIR}/*.c
    ${PROJECT_SOURCE_DIR}/*.cpp
    ${PROJECT_SOURCE_DIR}/*.rc
)

include_directories(
    ${CMAKE_SOURCE_DIR}/SDK/include
    ${CMAKE_SOURCE_DIR}/SDK/include/llapi
    ${CMAKE_SOURCE_DIR}/Header
)

link_directories(
    ${CMAKE_SOURCE_DIR}/SDK/lib
    ${CMAKE_SOURCE_DIR}/Lib
)

add_definitions(
    -D"NDEBUG"
    -D"NOMINMAX"
    -D"_AMD64_"
    -D"_CRT_SECURE_NO_WARNINGS"
    -D"_UNICODE"
    -D"_USRDLL"
    -D"_WINDLL"
    -D"_WINDOWS"
)

add_compile_options(
    /diagnostics:column
    /EHsc
    /FC
    /GL
    /nologo
    /permissive-
    /sdl
    /Zc:inline
    /Zi
    /MT
    /Zc:forScope
    /Zc:wchar_t
    /Zc:__cplusplus
    /Ob2
    /Oi
    /Ot
    /Oy
    /GT
    /Gy
)

add_link_options(
    /DEBUG
    /DELAYLOAD:"bedrock_server.dll"
    /DLL
    /IGNORE:4199
    /INCREMENTAL:NO
    /LTCG:INCREMENTAL
    /MANIFESTUAC:NO
    /MACHINE:X64
    /NOLOGO
    /OPT:ICF
    /OPT:REF
    /SUBSYSTEM:CONSOLE
)

add_library(LLWebsocketR SHARED ${SRC_FILES_DIR})

target_link_libraries(LLWebsocketR 
    "${CMAKE_SOURCE_DIR}/Lib/openssl/libcrypto.lib"
    "${CMAKE_SOURCE_DIR}/Lib/openssl/libssl.lib"
    "${CMAKE_SOURCE_DIR}/Lib/cryptlib.lib"
	"${CMAKE_SOURCE_DIR}/SDK/lib/LiteLoader.lib"
	"${CMAKE_SOURCE_DIR}/SDK/lib/bedrock_server_api.lib"
	"${CMAKE_SOURCE_DIR}/SDK/lib/bedrock_server_var.lib"
	"${CMAKE_SOURCE_DIR}/SDK/lib/SymDBHelper.lib"
)

add_custom_command(TARGET LLWebsocketR PRE_BUILD
    COMMAND cmd /c ${CMAKE_SOURCE_DIR}/prepare_libraries.cmd ${CMAKE_SOURCE_DIR}
)
