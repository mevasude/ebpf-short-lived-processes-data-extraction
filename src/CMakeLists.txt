# CMakeLists.txt for ebpf_loader_test
cmake_minimum_required(VERSION 3.15)

project(full_test)
include(ExternalProject)



set(libbpf_SOURCE_DIR ${CMAKE_SOURCE_DIR}/libbpf/src/libbpf)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/third_party)

#Fetch libbpf
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v1.0.1
    PREFIX ./libbpf
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cd ${libbpf_SOURCE_DIR}/src && bash -c "CFLAGS=\"-g -O2 -Werror -Wall -fPIC -fstack-protector-strong\" make"
    INSTALL_COMMAND cd ${libbpf_SOURCE_DIR}/src && DESTDIR=${CMAKE_SOURCE_DIR}/third_party make install
    BUILD_BYPRODUCTS ${libbpf_SOURCE_DIR}/src/libbpf.a
    )


set(TARGETNAME ebpf_prog_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)  # Avoid gnu++17
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")
else()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++")
endif()
# Add compiler flags to suppress warnings
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

include_directories(SYSTEM
    /usr/include/c++/12
    /usr/include/x86_64-linux-gnu/c++/12
)
# Development tool for developers
add_executable(${TARGETNAME} test.cpp)

# make ebpf_loader
add_definitions("-fPIC  -g -fstack-protector-strong")
add_dependencies(${TARGETNAME} libbpf)
# target_link_libraries(${TARGETNAME} -static-libstdc++ ${libbpf_SOURCE_DIR}/src/libbpf.a elf z pthread)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(${TARGETNAME} PRIVATE ${libbpf_SOURCE_DIR}/src/libbpf.a elf z pthread c++)
else()
    target_link_libraries(${TARGETNAME} PRIVATE ${libbpf_SOURCE_DIR}/src/libbpf.a elf z pthread stdc++)
endif()

target_include_directories(${TARGETNAME} PRIVATE
                           "${PROJECT_BINARY_DIR}"
                           "${libbpf_SOURCE_DIR}/src"
                           "${libbpf_SOURCE_DIR}/include"
                           "${libbpf_SOURCE_DIR}/include/asm"
                           "${libbpf_SOURCE_DIR}/include/linux"
                           "${libbpf_SOURCE_DIR}/include/tools"
                           "${libbpf_SOURCE_DIR}/include/uapi"
                           "${libbpf_SOURCE_DIR}/include/uapi/linux"
                           "/usr/include"
                           "/usr/include/c++/12"
                           "/usr/include/x86_64-linux-gnu/c++/12"
                           )


# list of ebpf programs to make
set(EBPF_PROGS
               test.bpf
)


# set binaries and options for clang and llc
set(CLANG "clang")
set(CLANG_CXX "clang++")
set(LLC "llc")
set(CLANG_OPTIONS ${CLANG_OPTIONS}
                -Wno-unused-value
                  -Wno-pointer-sign
                  -Wno-compare-distinct-pointer-types
                  -Wno-gnu-variable-sized-type-not-at-end
                  -Wno-address-of-packed-member
                  -Wno-tautological-compare
                  -Wno-unknown-warning-option
                  -Wno-int-conversion
                  )
set(CLANG_DEFINES -D __KERNEL__
                  -D __BPF_TRACING__
                  -D __TARGET_ARCH_x86
                  )
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
if (DEBUG_K)
    message("Using DEBUG_K Option...")
    list(APPEND CLANG_DEFINES -DDEBUG_K)
endif()

set(CLANG_INCLUDES 
                   -I "/usr/include"
                   -I "/usr/include/x86_64-linux-gnu"
                   -I "${CMAKE_SOURCE_DIR}"
                   -I "${CMAKE_SOURCE_DIR}/third_party/usr/include"
                   )

function(build_ebpf ebpfsrc ebpfout flags)
    add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/${ebpfout}.o
                       COMMAND "${CLANG}" -nostdinc -isystem `gcc -print-file-name=include` -target bpf ${CLANG_INCLUDES} ${CLANG_DEFINES} ${defines} ${flags} -O2 ${CLANG_OPTIONS} -emit-llvm -g -c "${CMAKE_SOURCE_DIR}/${ebpfsrc}.c" -o -| "${LLC}" -march=bpf -filetype=obj -o "${CMAKE_BINARY_DIR}/${ebpfout}.o"
                       COMMENT "Building EBPF object ${ebpfout}.o"
                       DEPENDS ${ebpfsrc}.c
                       DEPENDS libbpf
                       )
endfunction()

# Given a target, strips the symbols from it into a separate file
function(target_strip_symbols targetName isKernel)
    set(input $<TARGET_FILE:${targetName}>)
    set(output ${input}.dbg)

    add_custom_command(
        TARGET ${targetName} POST_BUILD VERBATIM
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta "Stripping symbols from ${input} into ${output} ..."
        COMMAND ${OBJCOPY} --only-keep-debug ${input} ${output}
        COMMAND ${OBJCOPY} --strip-unneeded ${input}
        COMMAND ${OBJCOPY} --add-gnu-debuglink=${output} ${input}
    )
endfunction()

#find_program(OBJCOPY objcopy)
#target_strip_symbols(${TARGETNAME} FALSE)

# loop for all ebpf programs
foreach(EBPF_PROG IN LISTS EBPF_PROGS)
    
    # add custom target to build all ebpf programs with 'all'
    add_custom_target(${EBPF_PROG} ALL
                      DEPENDS ${EBPF_PROG}.o
                      )

    if(${CMAKE_SOURCE_DIR}/${EBPF_PROG}.c IS_NEWER_THAN ${CMAKE_BINARY_DIR}/${EBPF_PROG}.o)
        build_ebpf(${EBPF_PROG} ${EBPF_PROG} "")
    endif()

    # add ebpf programs to clean
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_PROG}.o)
endforeach(EBPF_PROG)

