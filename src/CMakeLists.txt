cmake_minimum_required(VERSION 2.8)
project (petya_key_poc)

set (hdrs
	ec.h
	common.h
	endian.h
	aes256.h
)

set (srcs
	main.cpp
	aes256.cpp
)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lcrypto")
add_executable (petya_key_poc ${hdrs} ${srcs})

