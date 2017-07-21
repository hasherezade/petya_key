cmake_minimum_required(VERSION 2.8)
project (petya_key)

set (hdrs
	ec.h
	common.h
	endian.h
	aes256.h
	base58.h
)

set (srcs
	main.cpp
	aes256.cpp
	base58.cpp
)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lcrypto")
add_executable (petya_key ${hdrs} ${srcs})

