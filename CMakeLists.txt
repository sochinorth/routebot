cmake_minimum_required(VERSION 3.13)
project(routebot C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

option(WITH_UBUS "Resolve netifd logical interfaces via ubus" ON)

find_path(UBOX_INCLUDE_DIR libubox/uloop.h)
find_library(UBOX_LIBRARY NAMES ubox)
find_path(UCI_INCLUDE_DIR uci.h)
find_library(UCI_LIBRARY NAMES uci)
find_path(MNL_INCLUDE_DIR libmnl/libmnl.h)
find_library(MNL_LIBRARY NAMES mnl)

foreach(dep UBOX_INCLUDE_DIR UBOX_LIBRARY UCI_INCLUDE_DIR UCI_LIBRARY MNL_INCLUDE_DIR MNL_LIBRARY)
	if(NOT ${dep})
		message(FATAL_ERROR "${dep} not found")
	endif()
endforeach()

add_executable(routebot
	src/main.c
	src/config.c
	src/nl.c
	src/ifstate.c
	src/sync.c
	src/probe.c
	src/netifd.c
)
target_include_directories(routebot PRIVATE ${UBOX_INCLUDE_DIR} ${UCI_INCLUDE_DIR} ${MNL_INCLUDE_DIR})
target_link_libraries(routebot PRIVATE ${UCI_LIBRARY} ${UBOX_LIBRARY} ${MNL_LIBRARY})

if(WITH_UBUS)
	find_path(UBUS_INCLUDE_DIR libubus.h)
	find_library(UBUS_LIBRARY NAMES ubus)
	if(NOT UBUS_INCLUDE_DIR OR NOT UBUS_LIBRARY)
		message(FATAL_ERROR "libubus not found (or configure with -DWITH_UBUS=OFF)")
	endif()
	target_compile_definitions(routebot PRIVATE WITH_UBUS)
	target_include_directories(routebot PRIVATE ${UBUS_INCLUDE_DIR})
	target_link_libraries(routebot PRIVATE ${UBUS_LIBRARY})
endif()

install(TARGETS routebot RUNTIME DESTINATION sbin)

# Unit tests: every tests/unit/test_*.c becomes one ctest, linked with all of
# src/ but main.c (a test supplies log_level and log_msg itself). Absent
# from the OpenWrt package build, which only copies src/.
option(ROUTEBOT_UNIT_TESTS "Build and register tests/unit/test_*.c" OFF)
if(ROUTEBOT_UNIT_TESTS)
	enable_testing()
	file(GLOB ROUTEBOT_UNIT_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/test_*.c)
	get_target_property(ROUTEBOT_SOURCES routebot SOURCES)
	list(REMOVE_ITEM ROUTEBOT_SOURCES src/main.c)
	get_target_property(ROUTEBOT_INCLUDES routebot INCLUDE_DIRECTORIES)
	get_target_property(ROUTEBOT_LIBS routebot LINK_LIBRARIES)
	get_target_property(ROUTEBOT_DEFS routebot COMPILE_DEFINITIONS)
	foreach(src ${ROUTEBOT_UNIT_SOURCES})
		get_filename_component(name ${src} NAME_WE)
		add_executable(${name} ${src} ${ROUTEBOT_SOURCES})
		target_include_directories(${name} PRIVATE src ${ROUTEBOT_INCLUDES})
		target_link_libraries(${name} PRIVATE ${ROUTEBOT_LIBS})
		if(ROUTEBOT_DEFS)
			target_compile_definitions(${name} PRIVATE ${ROUTEBOT_DEFS})
		endif()
		# test_config_oom fails reallocs on purpose
		if(name STREQUAL "test_config_oom")
			target_link_options(${name} PRIVATE -Wl,--wrap=realloc)
		endif()
		add_test(NAME ${name} COMMAND ${name})
	endforeach()
endif()
