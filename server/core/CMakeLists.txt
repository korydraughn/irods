set(
  IRODS_SERVER_CORE_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/access_time_queue.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/administration_utilities.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/atomic_apply_database_operations.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/client_api_allowlist.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/catalog.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/catalog_utilities.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/collection.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/dataObjOpr.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/replica_access_table.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/replica_state_table.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/fileOpr.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/finalize_utilities.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/initServer.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_api_calling_functions.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_api_number_validator.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_collection_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_data_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_database_factory.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_database_manager.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_database_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_database_plugin.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_file_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_get_l1desc.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_report_plugins_in_json.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_mysql_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_oracle_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_physical_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_postgres_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_generic_database_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_resource_backport.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_resource_constants.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_resource_manager.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_resource_plugin.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_resource_plugin_impostor.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_resource_redirect.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_rs_comm_query.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_server_api_table.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_server_globals.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_server_negotiation.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_server_state.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_signal.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irods_structured_object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/json_deserialization.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/json_serialization.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/logical_locking.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/miscServerFunct.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/notify_service_manager.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/objDesc.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/objMetaOpr.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/physPath.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/plugin_lifetime_manager.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/replication_utilities.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/rodsConnect.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/rsApiHandler.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/rsIcatOpr.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/server_utilities.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/specColl.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/user_validation_utilities.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/voting.cpp"
)

set(
  IRODS_SERVER_CORE_HEADERS_PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/access_time_queue.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/administration_utilities.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/atomic_apply_database_operations.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/catalog.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/catalog_utilities.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/client_api_allowlist.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/collection.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/dataObjOpr.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/replica_access_table.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/replica_state_table.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/fileOpr.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/finalize_utilities.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/initServer.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_api_calling_functions.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_api_number_validator.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_collection_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_data_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_database_constants.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_database_factory.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_database_manager.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_database_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_database_plugin.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_database_types.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_delay_queue.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_file_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_generic_database_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_get_l1desc.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_linked_list_iterator.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_mysql_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_oracle_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_physical_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_postgres_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_report_plugins_in_json.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_resource_backport.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_resource_constants.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_resource_manager.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_resource_plugin.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_resource_plugin_impostor.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_resource_redirect.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_resource_types.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_rs_comm_query.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_server_api_call.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_server_api_table.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_server_state.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_signal.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irods_structured_object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/json_deserialization.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/json_serialization.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/logical_locking.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/miscServerFunct.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/notify_service_manager.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/objDesc.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/objMetaOpr.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/physPath.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/plugin_lifetime_manager.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/process_manager.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/replication_utilities.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/resource.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/rodsConnect.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/rsApiHandler.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/rsGlobalExtern.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/rsIcatOpr.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/scoped_client_identity.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/scoped_permission.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/scoped_privileged_client.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/server_utilities.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/specColl.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/user_validation_utilities.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/voting.hpp"
)

add_library(
  irods_server_core
  OBJECT
  "${IRODS_SERVER_CORE_SOURCES}"
  "${IRODS_SERVER_CORE_HEADERS_PUBLIC}"
)
objects_link_libraries(
  irods_server_core
  PUBLIC
  nlohmann_json::nlohmann_json
  fmt::fmt
  irods_common
  irods_plugin_dependencies
  PRIVATE
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_chrono.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_NANODBC}/lib/libnanodbc.so"
  OpenSSL::SSL
  OpenSSL::Crypto
  ${CMAKE_DL_LIBS}
  rt
)
target_include_directories(
  irods_server_core
  PUBLIC
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_IRODS_SOURCE_DIR}/plugins/api/include>"
  "$<BUILD_INTERFACE:${CMAKE_IRODS_SOURCE_DIR}/server/api/include>"
  "$<BUILD_INTERFACE:${CMAKE_IRODS_SOURCE_DIR}/server/main_server/include>"
  PRIVATE
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_NANODBC}/include"
)
target_compile_definitions(
  irods_server_core
  PUBLIC
  ${IRODS_COMPILE_DEFINITIONS_PUBLIC}
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  ENABLE_RE
  RODS_CLERVER
  IRODS_ENABLE_SYSLOG
)
set_target_properties(irods_server_core PROPERTIES INTERFACE_POSITION_INDEPENDENT_CODE TRUE)
set_target_properties(irods_server_core PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

if (IRODS_USE_LIBSYSTEMD)
  objects_link_libraries(irods_server_core PRIVATE systemd::libsystemd)
  target_compile_definitions(irods_server_core PRIVATE IRODS_USE_LIBSYSTEMD)
endif()

install(
  FILES ${IRODS_SERVER_CORE_HEADERS_PUBLIC}
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/irods"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_DEVELOPMENT_NAME}
)
