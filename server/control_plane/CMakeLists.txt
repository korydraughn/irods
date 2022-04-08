cmake_minimum_required(VERSION 3.12.0 FATAL_ERROR)
# target_link_libraries for object targets

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/include/irods/"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/include/irods/"
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/include/irods/server_control_plane_command.hpp"
  COMMAND "${CMAKE_COMMAND}" -E env LD_LIBRARY_PATH="${IRODS_EXTERNALS_FULLPATH_BOOST}/lib" "${IRODS_EXTERNALS_FULLPATH_AVRO}/bin/avrogencpp" -n irods -o "${CMAKE_CURRENT_BINARY_DIR}/include/irods/server_control_plane_command.hpp" -i "${CMAKE_IRODS_SOURCE_DIR}/irods_schema_messaging/v1/server_control_plane_command.json"
  MAIN_DEPENDENCY "${CMAKE_IRODS_SOURCE_DIR}/irods_schema_messaging/v1/server_control_plane_command.json"
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/include/irods/"
)

add_custom_target(
  irods_server_control_plane_command_hpp
  ALL
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/include/irods/server_control_plane_command.hpp"
)

add_dependencies(all-server irods_server_control_plane_command_hpp)
install(
  FILES
  "${CMAKE_CURRENT_BINARY_DIR}/include/irods/server_control_plane_command.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/irods"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_DEVELOPMENT_NAME}
)

add_library(
  irods_server_control_plane
  INTERFACE
)
target_link_libraries(
  irods_server_control_plane
  INTERFACE
  irods_common
)
target_include_directories(
  irods_server_control_plane
  INTERFACE
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>"
)
add_dependencies(
  irods_server_control_plane
  irods_server_control_plane_command_hpp
)

#####################
add_executable(
  irodsControlPlane
  "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
)
target_link_libraries(
  irodsControlPlane
  PRIVATE
  irods_common
  irods_plugin_dependencies
  irods_server
  irods_server_control_plane
  "${IRODS_EXTERNALS_FULLPATH_AVRO}/lib/libavrocpp.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_chrono.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_program_options.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
  "${IRODS_EXTERNALS_FULLPATH_ZMQ}/lib/libzmq.so"
  rt
  ${CMAKE_DL_LIBS}
  m
)
target_include_directories(
  irodsControlPlane
  PRIVATE
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "${IRODS_EXTERNALS_FULLPATH_AVRO}/include"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_CPPZMQ}/include"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
  "${IRODS_EXTERNALS_FULLPATH_ZMQ}/include"
  "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
)
target_compile_definitions(
  irodsControlPlane
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  ENABLE_RE # TODO Is this needed?
  IRODS_ENABLE_SYSLOG
)

add_dependencies(all-server irodsControlPlane)
install(
  TARGETS
  irodsControlPlane
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_SERVER_NAME}
)
#####################

install(
  FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_server_control_plane.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/irods"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_DEVELOPMENT_NAME}
)
