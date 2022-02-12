cmake_minimum_required(VERSION 3.21)
project(LLMods)

set(CMAKE_CXX_STANDARD 17)

include_directories(Shared/Header)
include_directories(Shared/Lib)
include_directories(WebsocketServer)

add_definitions(-DUNICODE -DNDEBUG -DLITELOADER_EXPORTS -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -D_WINDOWS -D_USRDLL -D_AMD64_ -DNOMINMAX)

file(GLOB SRC_FILES
        ${PROJECT_SOURCE_DIR}/Shared/*.cpp
        ${PROJECT_SOURCE_DIR}/Shared/*.hpp
        ${PROJECT_SOURCE_DIR}/Shared/*.h
        ${PROJECT_SOURCE_DIR}/WebsocketServer/*.cpp
        ${PROJECT_SOURCE_DIR}/WebsocketServer/*.hpp
        ${PROJECT_SOURCE_DIR}/WebsocketServer/*.h
        )

add_compile_options(
        /permissive
        /GS
        /GL
        /W2
        /Gy
        /Zc:wchar_t
        /Zi
        /Gm-
        /Od
        /sdl
        /Zc:inline
        /fp:precise
        /errorReport:prompt
        /WX-
        /Zc:forScope
        /Gd
        /Oi
        /MD
        /EHa
        /nologo
        /diagnostics:column
        /utf-8
        /LTCG
)

add_library(WebsocketServer SHARED ${SRC_FILES})
