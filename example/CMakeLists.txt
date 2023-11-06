cmake_minimum_required (VERSION 3.16...3.19)

set(PROJECTNAME git2example)

project(${PROJECTNAME})

add_executable(${PROJECTNAME} main.cpp)

target_link_libraries(${PROJECTNAME} 
    PRIVATE
        libgit2
        libgit2package)