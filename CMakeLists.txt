cmake_minimum_required(VERSION 3.16)
project(WatchPort LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

add_executable(watchport
  src/main.cpp
  src/scanner.cpp
  src/vulnerability.cpp
)
target_link_libraries(watchport PRIVATE Threads::Threads)
if(WIN32)
  target_link_libraries(watchport PRIVATE ws2_32)
endif()

# The logo is optional, but copy it next to the executable so it can be found.
add_custom_command(TARGET watchport POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          ${CMAKE_SOURCE_DIR}/assets $<TARGET_FILE_DIR:watchport>/assets)
