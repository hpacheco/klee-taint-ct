#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
add_executable(kleaver
  main.cpp
)

set(KLEE_LIBS
  kleaverSolver
)

add_library(libcryptominisat4 STATIC IMPORTED)
set_target_properties(libcryptominisat4 PROPERTIES IMPORTED_LOCATION /usr/lib/libcryptominisat4.a)
set_target_properties(libcryptominisat4 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES /usr/include)

target_link_libraries(kleaver ${KLEE_LIBS} libcryptominisat4)

install(TARGETS kleaver RUNTIME DESTINATION bin)
