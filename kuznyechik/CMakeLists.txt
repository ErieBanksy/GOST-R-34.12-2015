set(TARGET_NAME Kuznyechik)

message(STATUS "Creating and configuration target ${TARGET_NAME}.")
add_executable (${TARGET_NAME}
        main.cpp
        gost12_15.h
        gost12_15.cpp)
set_target_properties(${TARGET_NAME} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

# Include
target_include_directories(${TARGET_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/kuznyechik/")

# Link
target_link_libraries(${TARGET_NAME} PRIVATE "")

