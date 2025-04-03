cmake_minimum_required (VERSION 3.5.1)

project(demo CXX)
set(CMAKE_CXX_STANDARD 17)

option(BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenSSL REQUIRED)

find_package(OpenFHE CONFIG REQUIRED)
if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif()

# Use the compiler flags from OpenFHE
set(CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS})

# Include paths for OpenFHE + (optionally) OpenMP
include_directories(
    ${OPENMP_INCLUDES}
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/third-party/include
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)

# Where to find libraries
link_directories(
    ${OpenFHE_LIBDIR}
    ${OPENMP_LIBRARIES}
)

# Handle static vs. shared linking with OpenFHE
if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
else()
    set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS}")
endif()

add_library(psmt_malicious
    ${PROJECT_SOURCE_DIR}/src/evenPS.cpp
    ${PROJECT_SOURCE_DIR}/src/utilsPS.cpp
    ${PROJECT_SOURCE_DIR}/src/dep.cpp
    ${PROJECT_SOURCE_DIR}/src/chebyshev_config.cpp
    ${PROJECT_SOURCE_DIR}/src/fhe_init.cpp
    ${PROJECT_SOURCE_DIR}/src/vaf.cpp
    ${PROJECT_SOURCE_DIR}/src/tests.cpp
    ${PROJECT_SOURCE_DIR}/src/core.cpp
    ${PROJECT_SOURCE_DIR}/hashing/hash.cpp
    ${PROJECT_SOURCE_DIR}/hashing/test.cpp
    ${PROJECT_SOURCE_DIR}/logreg/core.cpp
    ${PROJECT_SOURCE_DIR}/logreg/tests.cpp
    ${PROJECT_SOURCE_DIR}/logreg/utils.cpp
    ${PROJECT_SOURCE_DIR}/psmt/server.cpp
    ${PROJECT_SOURCE_DIR}/psmt/client.cpp
    ${PROJECT_SOURCE_DIR}/psmt/tests.cpp
    # For PEPSI
    ${PROJECT_SOURCE_DIR}/pepsi/core.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/server.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/client.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/tests.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/fhe_init.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/main_pepsi.cpp

)

# Let the library see your include/ folder
target_include_directories(psmt_malicious PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/logreg
    ${PROJECT_SOURCE_DIR}/hashing
    ${PROJECT_SOURCE_DIR}/pepsi
)

# Link OpenFHE 
if(BUILD_STATIC)
    target_link_libraries(psmt_malicious PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(psmt_malicious PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()

##################################################
# 1) Build the main executable from main.cpp
##################################################
add_executable(main
    ${PROJECT_SOURCE_DIR}/src/main.cpp
)

# Let main see your include/ folder
target_include_directories(main PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

# Finally, link main with:
target_link_libraries(main PRIVATE psmt_malicious)


##################################################
# 2) Build the main executable from main_vaf.cpp
##################################################

add_executable(main_vaf
    ${PROJECT_SOURCE_DIR}/src/main_vaf.cpp
)

# Let main_vaf see your include/ folder
target_include_directories(main_vaf PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

# Finally, link main_vaf:

target_link_libraries(main_vaf PRIVATE psmt_malicious)

##################################################
# 2) Build the main executable from main_vaf.cpp
##################################################

add_executable(main_hash
    ${PROJECT_SOURCE_DIR}/hashing/main_hash.cpp
)

# Let main_vaf see your include/ folder
target_include_directories(main_hash PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/hashing
)

# Finally, link main_vaf:

target_link_libraries(main_hash PRIVATE psmt_malicious OpenSSL::SSL OpenSSL::Crypto)


##################################################
# 2) Build the main executable from main_vaf.cpp
##################################################

add_executable(main_logreg
    ${PROJECT_SOURCE_DIR}/logreg/main_logreg.cpp
)

# Let main_vaf see your include/ folder
target_include_directories(main_logreg PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/logreg
)

# Finally, link main_vaf:

target_link_libraries(main_logreg PRIVATE psmt_malicious)

##################################################
# 2) Build the main executable from main_vaf.cpp
##################################################

add_executable(main_psmt
    ${PROJECT_SOURCE_DIR}/psmt/main_psmt.cpp
)

# Let main_vaf see your include/ folder
target_include_directories(main_hash PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/psmt
)

# Finally, link main_vaf:

target_link_libraries(main_psmt PRIVATE psmt_malicious)


##################################################
# 2) Build the main executable from main_vaf.cpp
##################################################

add_executable(main_pepsi
    ${PROJECT_SOURCE_DIR}/pepsi/main_pepsi.cpp
)

# Let main_vaf see your include/ folder
target_include_directories(main_pepsi PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/pepsi
)

# Finally, link main_vaf:

target_link_libraries(main_pepsi PRIVATE psmt_malicious)
