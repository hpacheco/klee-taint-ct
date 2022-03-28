#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
if (HAVE_PTY_H)
  add_executable(klee-replay
    fd_init.c
    file-creator.c
    klee-replay.c
    klee_init_env.c
  )
  add_library(libcryptominisat4 STATIC IMPORTED)
  set_target_properties(libcryptominisat4 PROPERTIES IMPORTED_LOCATION /usr/lib/libcryptominisat4.a)
  set_target_properties(libcryptominisat4 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES /usr/include)

  target_link_libraries(klee-replay PRIVATE kleeBasic ${LIBCAP_LIBRARIES} libcryptominisat4)
  # FIXME: This isn't quite right. This is actually an implementation detail
  # of glibc not Linux. Really we need to test if we can use `openpty()`
  # with/without an additional library.
  if ("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
    if (NOT LIBUTIL_LIBRARIES)
      message(FATAL_ERROR "klee-replay needs libutil under Linux")
    endif()
    target_link_libraries(klee-replay PRIVATE ${LIBUTIL_LIBRARIES})
  endif()
install(TARGETS klee-replay RUNTIME DESTINATION bin)
else()
  message(WARNING "Not building klee-replay due to missing \"pty.h\" header file")
endif()
