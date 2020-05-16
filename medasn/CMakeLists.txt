#cmake_minimum_required(VERSION 3.5)
cmake_minimum_required(VERSION 3.0.0)
project(medasn
	VERSION 0.1.0
	LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
	${PROJECT_SOURCE_DIR}/../${PROJECT_NAME}
	${PROJECT_SOURCE_DIR}/../med
	${PROJECT_SOURCE_DIR}/../PEGTL/include
)

#include(CheckCXXCompilerFlag)
#check_cxx_compiler_flag("-std=c++17" COMPILER_SUPPORTS_CXX17)
#if (COMPILER_SUPPORTS_CXX17)
#	add_compile_options(-std=c++17)
#else ()
#	message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support. Please use a different C++ compiler.")
#endif ()

set(MEDASN_SRC
	medasn.cpp
)

add_compile_options(
	-Werror
	-Wall
	-Wextra
	-Waddress
	-Warray-bounds
	-Winit-self
	-Wunreachable-code
	-pedantic
	-pedantic-errors
	-mtune=native
)

add_executable(${PROJECT_NAME} ${MEDASN_SRC})

#set(CPACK_PROJECT_NAME ${PROJECT_NAME})
#set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)
