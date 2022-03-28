#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
add_executable(gen-random-bout
  gen-random-bout.cpp
)

set(KLEE_LIBS kleeBasic)

add_library(libcryptominisat4 STATIC IMPORTED)
set_target_properties(libcryptominisat4 PROPERTIES IMPORTED_LOCATION /usr/lib/libcryptominisat4.a)
set_target_properties(libcryptominisat4 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES /usr/include)

target_link_libraries(gen-random-bout ${KLEE_LIBS} libcryptominisat4)

install(TARGETS gen-random-bout RUNTIME DESTINATION bin)
