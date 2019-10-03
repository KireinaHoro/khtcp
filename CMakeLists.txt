cmake_minimum_required(VERSION 3.8)

project(KHTcp)

set(lib_name "khtcp")
set(CMAKE_CXX_STANDARD_REQUIRED 17)

file(GLOB proj_headers "include/*.h")
file(GLOB proj_sources "src/*.cc")

set(utils_root "${PROJECT_SOURCE_DIR}/cmake")
file(GLOB cmake_utils "${utils_root}/*.cmake")
foreach(util IN LISTS cmake_utils)
    include(${util})
endforeach(util IN LISTS cmake_utils)

find_package(Boost 1.69.0 EXACT REQUIRED COMPONENTS log)
include_directories("include/" ${Boost_INCLUDE_DIRS} ${PCAP_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES} ${PCAP_LIBRARIES})
add_definitions(-DBOOST_LOG_DYN_LINK)


add_library(${lib_name} SHARED ${proj_headers} ${proj_sources})

add_subdirectory(tests)
