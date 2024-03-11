cmake_minimum_required(VERSION 3.25)
project(packets)

set(CMAKE_CXX_STANDARD 17)

add_executable(
        ${PROJECT_NAME}
        main.cpp
        packets/reader/reader.h
        packets/reader/reader.cpp
        packets/analyzer/analyzer.h
        packets/analyzer/analyzer.cpp
)
