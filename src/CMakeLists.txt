cmake_minimum_required(VERSION 2.8)
project (petya_key)

set (hdrs
	ec.h
	common.h
	endian.h
	base58.h
	petya.h
)

set (srcs
	main.cpp
	base58.cpp
	petya.cpp
)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lcrypto")

add_executable (${PROJECT_NAME} ${hdrs} ${srcs})

