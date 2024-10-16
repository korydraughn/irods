add_executable(
  irodsServer5
  "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
)
target_link_libraries(
  irodsServer5
  PRIVATE
  fmt::fmt
  irods_common
  irods_plugin_dependencies
  irods_server
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_chrono.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  #"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_program_options.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  #"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
  #"${IRODS_EXTERNALS_FULLPATH_ZMQ}/lib/libzmq.so"
  rt
  ${CMAKE_DL_LIBS}
  m
)
target_include_directories(
  irodsServer5
  PRIVATE
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/third_party>"
  #"${IRODS_EXTERNALS_FULLPATH_AVRO}/include"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  #"${IRODS_EXTERNALS_FULLPATH_CPPZMQ}/include"
  #"${IRODS_EXTERNALS_FULLPATH_ZMQ}/include"
)
target_compile_definitions(
  irodsServer5
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  ENABLE_RE
  IRODS_ENABLE_SYSLOG
)

add_dependencies(all-server irodsServer5)
install(
  TARGETS
  irodsServer5
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_SERVER_NAME}
)

add_executable(
  irodsAgent5
  "${CMAKE_CURRENT_SOURCE_DIR}/src/agent_main.cpp"
)
target_link_libraries(
  irodsAgent5
  PRIVATE
  fmt::fmt
  irods_common
  irods_plugin_dependencies
  irods_server
  #"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_chrono.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  #"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_program_options.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  #"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
  #"${IRODS_EXTERNALS_FULLPATH_ZMQ}/lib/libzmq.so"
  rt
  ${CMAKE_DL_LIBS}
  m
)
target_include_directories(
  irodsAgent5
  PRIVATE
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  #"${IRODS_EXTERNALS_FULLPATH_AVRO}/include"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  #"${IRODS_EXTERNALS_FULLPATH_CPPZMQ}/include"
  #"${IRODS_EXTERNALS_FULLPATH_ZMQ}/include"
)
target_compile_definitions(
  irodsAgent5
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  ENABLE_RE
  IRODS_ENABLE_SYSLOG
)

add_dependencies(all-server irodsAgent5)
install(
  TARGETS
  irodsAgent5
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_SERVER_NAME}
)
