#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
add_executable(klee
  main.cpp
)

set(KLEE_LIBS
  kleeCore
)

add_library(libcryptominisat4 STATIC IMPORTED)
set_target_properties(libcryptominisat4 PROPERTIES IMPORTED_LOCATION /usr/lib/libcryptominisat4.a)
set_target_properties(libcryptominisat4 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES /usr/include)

target_link_libraries(klee ${KLEE_LIBS} libcryptominisat4)

install(TARGETS klee RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(klee BuildKLEERuntimes)
