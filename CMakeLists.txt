cmake_minimum_required(VERSION 3.25)
project(Packets)

set(CMAKE_CXX_STANDARD 17)

add_executable(
        ${PROJECT_NAME}
        main.cpp
        Packets/Reader/Reader.h
        Packets/Reader/Reader.cpp
        Packets/Analyzer/Analyzer.h
        Packets/Analyzer/Analyzer.cpp
)
