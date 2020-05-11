cmake_minimum_required(VERSION 3.16)
project(Prac3 C)

set(CMAKE_C_STANDARD 11)

add_executable(rc4 rc4.c rc4.h)
add_executable(rsakeygen rsakeygen.c rsakeygen.h)
add_executable(rsaencrypt rsaencrypt.c rsaencrypt.h)
add_executable(rsadecrypt rsadecrypt.c rsadecrypt.h)