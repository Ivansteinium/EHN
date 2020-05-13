cmake_minimum_required(VERSION 3.15)
project(Prac3 C)

set(CMAKE_C_STANDARD 11)

include_directories(/usr/local/gmp-6.2.0)
link_libraries(gmp)

add_executable(rc4 rc4.c rc4.h)
add_executable(rsakeygen rsakeygen.c rsakeygen.h)
add_executable(rsaencrypt rsaencrypt.c rsaencrypt.h)
add_executable(rsadecrypt rsadecrypt.c rsadecrypt.h)