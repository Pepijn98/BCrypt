cmake_minimum_required(VERSION 3.12)
project(BCrypt)

file(GLOB_RECURSE swiftFiles *.swift)

add_custom_target(BCrypt ALL
        COMMAND /home/kurozero/.swiftenv/versions/4.2-DEVELOPMENT-SNAPSHOT-2018-09-14-a/usr/bin/swift build
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        SOURCES ${swiftFiles})
