set(_IRODS_MICROSERVICE_TEST_PLUGINS_BUILD_DOCSTR "Build microservice plugins designed for testing.")
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(_IRODS_MICROSERVICE_TEST_PLUGINS_BUILD_DEFAULT ON)
else()
  set(_IRODS_MICROSERVICE_TEST_PLUGINS_BUILD_DEFAULT OFF)
endif()

set(IRODS_MICROSERVICE_TEST_PLUGINS_BUILD ${_IRODS_MICROSERVICE_TEST_PLUGINS_BUILD_DEFAULT} CACHE BOOL "${_IRODS_MICROSERVICE_TEST_PLUGINS_BUILD_DOCSTR}")

if (IRODS_ENABLE_ALL_TESTS)
  set(IRODS_MICROSERVICE_TEST_PLUGINS_BUILD ON CACHE BOOL "${_IRODS_MICROSERVICE_TEST_PLUGINS_BUILD_DOCSTR}" FORCE)
endif()

# create phony target to build everything in plugins/microservices folder
add_custom_target(all-plugins-microservices)
add_dependencies(all-plugins_no_database all-plugins-microservices)

set(
  IRODS_MICROSERVICE_PLUGINS
  atomic_apply_acl_operations
  atomic_apply_metadata_operations
  get_agent_pid
  get_file_descriptor_info
  get_hostname
  get_open_data_obj_l1desc_index
  get_server_property
  json_compare
  json_contains
  json_dump
  json_free
  json_handles
  json_names
  json_parse
  json_size
  json_type
  json_value
  sync_to_archive
  touch
  update_unixfilesystem_resource_free_space
)

if (IRODS_MICROSERVICE_TEST_PLUGINS_BUILD)
  list(APPEND IRODS_MICROSERVICE_PLUGINS test_delay_rule_locking_api)
  list(APPEND IRODS_MICROSERVICE_PLUGINS test_issue_6782)
  list(APPEND IRODS_MICROSERVICE_PLUGINS test_issue_6829)
  list(APPEND IRODS_MICROSERVICE_PLUGINS test_msp_functions)
  list(APPEND IRODS_MICROSERVICE_PLUGINS test_scoped_client_identity)
  list(APPEND IRODS_MICROSERVICE_PLUGINS test_scoped_permission)
  list(APPEND IRODS_MICROSERVICE_PLUGINS test_user_administration)
endif()

foreach(plugin IN LISTS IRODS_MICROSERVICE_PLUGINS)
  string(TOUPPER ${plugin} PLUGIN_UPPERCASE)
  set(plugin_target "irods_microservice_plugin-${plugin}")
  set(plugin_name "msi_${plugin}")

  add_library(
    ${plugin_target}
    MODULE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/${plugin}.cpp"
  )
  set_property(TARGET ${plugin_target} PROPERTY LIBRARY_OUTPUT_NAME ${plugin_name})
  target_link_libraries(
    ${plugin_target}
    PRIVATE
    irods_common
    irods_server
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
    fmt::fmt
  )
  target_include_directories(
    ${plugin_target}
    PRIVATE
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  )
  target_compile_definitions(
    ${plugin_target}
    PRIVATE
    ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
    ENABLE_RE
    IRODS_ENABLE_SYSLOG
  )

  add_dependencies(all-plugins-microservices ${plugin_target})
  install(
    TARGETS
    ${plugin_target}
    LIBRARY
    DESTINATION "${IRODS_PLUGINS_DIRECTORY}/microservices"
    COMPONENT ${IRODS_PACKAGE_COMPONENT_SERVER_NAME}
  )
endforeach()

set_property(TARGET irods_microservice_plugin-sync_to_archive PROPERTY LIBRARY_OUTPUT_NAME msisync_to_archive)
