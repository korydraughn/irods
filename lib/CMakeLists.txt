# create irods_common target first, as it's needed in core
add_library(
  irods_common
  SHARED
)

# create phony target to build everything in lib folder
add_custom_target(all-lib)

add_subdirectory(core)
add_subdirectory(genquery1)
add_subdirectory(api)
add_subdirectory(filesystem)
add_subdirectory(administration)
add_subdirectory(hasher)
add_subdirectory(metadata)

target_link_objects(
  irods_common
  PUBLIC
  irods_filesystem_path
  irods_common_core
  irods_genquery1_parser
  irods_hasher
)
target_link_libraries(
  irods_common
  PRIVATE
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_program_options.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_random.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  OpenSSL::SSL
  ${CMAKE_DL_LIBS}
  rt
  CURL::libcurl
)
set_property(TARGET irods_common PROPERTY VERSION ${IRODS_VERSION})
set_property(TARGET irods_common PROPERTY SOVERSION ${IRODS_VERSION})

target_deduplicate_interface_properties(
  irods_common
  COMPILE_DEFINITIONS
  INCLUDE_DIRECTORIES
  LINK_LIBRARIES
)

add_dependencies(all-lib irods_common)
install(
  TARGETS
  irods_common
  EXPORT IRODSTargets
  LIBRARY
  DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_RUNTIME_NAME}
  NAMELINK_COMPONENT ${IRODS_PACKAGE_COMPONENT_DEVELOPMENT_NAME}
)

add_library(
  irods_client
  SHARED
)
target_link_objects(
  irods_client
  PUBLIC
  irods_lib_api_client
  irods_lib_core_client
  irods_filesystem_path
  irods_filesystem_client
  irods_user_administration_client
  irods_resource_administration_client
  irods_lib_metadata_client
  irods_ticket_administration_client
  irods_zone_administration_client
)
target_link_libraries(
  irods_client
  PUBLIC
  irods_plugin_dependencies
  irods_common
  PRIVATE
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_chrono.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
  OpenSSL::SSL
  OpenSSL::Crypto
  ${CMAKE_DL_LIBS}
)
set_property(TARGET irods_client PROPERTY VERSION ${IRODS_VERSION})
set_property(TARGET irods_client PROPERTY SOVERSION ${IRODS_VERSION})

target_deduplicate_interface_properties(
  irods_client
  COMPILE_DEFINITIONS
  INCLUDE_DIRECTORIES
  LINK_LIBRARIES
)

add_dependencies(all-lib irods_client)
install(
  TARGETS
  irods_client
  EXPORT IRODSTargets
  LIBRARY
  DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_RUNTIME_NAME}
  NAMELINK_COMPONENT ${IRODS_PACKAGE_COMPONENT_DEVELOPMENT_NAME}
)

add_library(
  RodsAPIs
  STATIC
)
target_link_objects(
  RodsAPIs
  PUBLIC
  irods_common_core
  irods_hasher
  irods_lib_api_client
  irods_lib_core_client
  irods_filesystem_path
  irods_filesystem_client
  irods_filesystem_server
  irods_user_administration_client
  irods_user_administration_server
  irods_resource_administration_client
  irods_resource_administration_server
  irods_ticket_administration_client
  irods_ticket_administration_server
  irods_plugin_dependencies_obj
  irods_lib_metadata_client
  irods_zone_administration_client
  irods_zone_administration_server
)
target_link_libraries(
  RodsAPIs
  PUBLIC
  nlohmann_json::nlohmann_json
  OpenSSL::Crypto
  OpenSSL::SSL
  CURL::libcurl
  Threads::Threads
  PRIVATE
  ${CMAKE_DL_LIBS}
  rt
)
target_compile_definitions(RodsAPIs PRIVATE ${IRODS_COMPILE_DEFINITIONS_PRIVATE})

target_deduplicate_interface_properties(
  RodsAPIs
  COMPILE_DEFINITIONS
  INCLUDE_DIRECTORIES
  LINK_LIBRARIES
)

add_dependencies(all-lib RodsAPIs)
install(
  TARGETS
  RodsAPIs
  EXPORT IRODSTargets
  ARCHIVE
  DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_DEVELOPMENT_NAME}
)

