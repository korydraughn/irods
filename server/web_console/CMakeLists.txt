add_executable(
  irodsWebConsole
  "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
)
target_link_libraries(
  irodsWebConsole
  PRIVATE
  fmt::fmt
# irods_common
# irods_plugin_dependencies
# irods_server
  irods_client
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_chrono.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_program_options.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  rt
  ${CMAKE_DL_LIBS}
  m
)
target_include_directories(
  irodsWebConsole
  PRIVATE
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
)
target_compile_definitions(
  irodsWebConsole
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
# ENABLE_RE
# IRODS_ENABLE_SYSLOG
)

add_dependencies(all-server irodsWebConsole)
install(
  TARGETS
  irodsWebConsole
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_SERVER_NAME}
)
