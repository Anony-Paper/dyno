cmake_minimum_required(VERSION 3.16)
project(dyno)

set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

# Static PathORam: Time-4
add_executable(time_static_path_oram-4 src/cmd/timeit/static_path_oram/time_all.cc)
target_compile_definitions(time_static_path_oram-4 PUBLIC VAL_LEN=4)
target_link_libraries(time_static_path_oram-4 ${CONAN_LIBS})
# Static PathORam: Time-32
add_executable(time_static_path_oram-32 src/cmd/timeit/static_path_oram/time_all.cc)
target_compile_definitions(time_static_path_oram-32 PUBLIC VAL_LEN=32)
target_link_libraries(time_static_path_oram-32 ${CONAN_LIBS})

# Static PathOMap: Time
add_executable(time_static_path_omap src/cmd/timeit/static_path_omap/time_all.cc src/static/omap/path_avl/omap.cc)
target_link_libraries(time_static_path_omap ${CONAN_LIBS})

# Dynamic Stepping PathORam: Time
add_executable(time_all_but_alloc_dynamic_stepping_path_oram src/cmd/timeit/dynamic_stepping_path_oram/all_but_alloc.cc)
target_link_libraries(time_all_but_alloc_dynamic_stepping_path_oram ${CONAN_LIBS})

# Dynamic Stepping PathOMap: Time
add_executable(time_all_but_alloc_dynamic_stepping_path_omap src/cmd/timeit/dynamic_stepping_path_omap/all_but_alloc.cc src/dynamic/omap/stepping_path/omap.cc src/static/omap/path_avl/omap.cc)
target_link_libraries(time_all_but_alloc_dynamic_stepping_path_omap ${CONAN_LIBS})

# Static PathOHeap: Time
add_executable(time_static_path_oheap src/cmd/timeit/static_path_oheap/time_all.cc src/static/oheap/path/oheap.cc)
target_link_libraries(time_static_path_oheap ${CONAN_LIBS})

# Dynamic Stepping PathOHeap: Time
add_executable(time_all_but_alloc_dynamic_stepping_path_oheap src/cmd/timeit/dynamic_stepping_path_oheap/all_but_alloc.cc src/dynamic/oheap/stepping_path/oheap.cc src/static/oheap/path/oheap.cc)
target_link_libraries(time_all_but_alloc_dynamic_stepping_path_oheap ${CONAN_LIBS})

# Static PathOStack: Time
add_executable(time_static_path_ostack src/cmd/timeit/static_path_ostack/time_all.cc src/static/ostack/path/ostack.cc)
target_link_libraries(time_static_path_ostack ${CONAN_LIBS})

# Static PlaintextStack: Time
add_executable(time_plaintext_stack src/cmd/timeit/plaintext_stack/time_all.cc)
target_link_libraries(time_plaintext_stack ${CONAN_LIBS})
