set(IRODS_TEST_TARGET irods_rc_switch_user)

set(IRODS_TEST_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/test_rc_switch_user.cpp)

set(IRODS_TEST_INCLUDE_PATH ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)
 
set(IRODS_TEST_LINK_LIBRARIES irods_client
                              ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so)

