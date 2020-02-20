cmake_minimum_required(VERSION 3.14)
project(EHN_Prac1 C)

set(CMAKE_C_STANDARD 11)
set(GCC_COVERAGE_COMPILE_FLAGS "-pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )

include_directories(/usr/local/ssl)
link_libraries(ssl)
link_libraries(crypto)



#-lpthread pthread1.c  client.c client.h
add_executable(EHN_Prac1 main.c)
add_executable(Client client.c)

#set(LDFLAGS -L/usr/local/ssl)
#set(LDLIBS -lssl -lcrypto)