#include <catch2/catch.hpp>

#include "irods/switch_user.h"
#include "irods/client_connection.hpp"
#include "irods/transport/default_transport.hpp"
#include "irods/dstream.hpp"
#include "irods/filesystem.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/rodsClient.h"
#include "irods/rodsUser.h"
#include "irods/user_administration.hpp"

// clang-format off
namespace adm = irods::experimental::administration;
namespace fs  = irods::experimental::filesystem;
namespace io  = irods::experimental::io;
// clang-format on

TEST_CASE("rc_switch_user basic usage")
{
    //
    // IMPORTANT: This test requires access to a rodsadmin user!
    //

    load_client_api_plugins();

    rodsEnv env;
    _getRodsEnv(env);

    const fs::path sandbox = "/tempZone/home/public/unit_testing_sandbox";
    irods::experimental::client_connection conn;

    if (!fs::client::exists(conn, sandbox)) {
        REQUIRE(fs::client::create_collection(conn, sandbox));
    }

    irods::at_scope_exit remove_sandbox{
        [&conn, &sandbox] { REQUIRE(fs::client::remove_all(conn, sandbox, fs::remove_options::no_trash)); }};

    // As the administrator, create a data object.
    auto data_object = sandbox / "foo";
    io::client::native_transport tp{conn};
    io::odstream{tp, data_object} << "some data";
    REQUIRE(fs::client::is_data_object(conn, data_object));

    // Create a test user.
    const adm::user alice{"test_user_alice"};
    REQUIRE(adm::client::add_user(conn, alice).value() == 0);

    irods::at_scope_exit remove_test_user{
        [&conn, &alice] { REQUIRE(adm::client::remove_user(conn, alice).value() == 0); }};

    // Give the test user permission to see the admin's data object and the contents of
    // the sandbox collection.
    fs::client::permissions(conn, sandbox, alice.name, fs::perms::write);
    fs::client::permissions(conn, data_object, alice.name, fs::perms::read);

    // Become the test user.
    auto* conn_ptr = static_cast<RcComm*>(conn);
    REQUIRE(rc_switch_user(conn_ptr, alice.name.c_str(), alice.zone.c_str()) == 0);
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    CHECK(conn_ptr->clientUser.userName == alice.name);
    CHECK(conn_ptr->clientUser.rodsZone == alice.zone);
    CHECK(std::strcmp(conn_ptr->clientUser.userType, adm::to_c_str(adm::user_type::rodsuser)) == 0);
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    CHECK(conn_ptr->clientUser.authInfo.authFlag == LOCAL_USER_AUTH);

    // As the test user, create another data object in the sandbox.
    data_object = sandbox / "bar";
    io::odstream{tp, data_object} << "other data";
    REQUIRE(fs::client::is_data_object(conn, data_object));

    // Show that there are two data objects in the collection.
    CHECK(std::distance(fs::client::collection_iterator{conn, sandbox}, fs::client::collection_iterator{}) == 2);

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

    // Give the administrator OWN permissions on the data object created by the test user.
    // This allows the administrator to remove the sandbox collection without issues.
    fs::client::permissions(conn, data_object, env.rodsUserName, fs::perms::own);

    REQUIRE(rc_switch_user(conn_ptr, env.rodsUserName, env.rodsZone) == 0);
    CHECK(std::strcmp(conn_ptr->clientUser.userName, env.rodsUserName) == 0);
    CHECK(std::strcmp(conn_ptr->clientUser.rodsZone, env.rodsZone) == 0);
    CHECK(std::strcmp(conn_ptr->clientUser.userType, adm::to_c_str(adm::user_type::rodsadmin)) == 0);
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    CHECK(conn_ptr->clientUser.authInfo.authFlag == LOCAL_PRIV_USER_AUTH);
}

TEST_CASE("rc_switch_user honors permission model following successful invocation")
{
    //
    // IMPORTANT: This test requires access to a rodsadmin user!
    //

    load_client_api_plugins();

    rodsEnv env;
    _getRodsEnv(env);

    const auto sandbox = fs::path{static_cast<const char*>(env.rodsHome)} / "unit_testing_sandbox";
    irods::experimental::client_connection conn;

    if (!fs::client::exists(conn, sandbox)) {
        REQUIRE(fs::client::create_collection(conn, sandbox));
    }

    irods::at_scope_exit remove_sandbox{
        [&conn, &sandbox] { REQUIRE(fs::client::remove_all(conn, sandbox, fs::remove_options::no_trash)); }};

    // As the administrator, create a data object.
    const auto data_object = sandbox / "foo";
    io::client::native_transport tp{conn};
    io::odstream{tp, data_object} << "data";
    REQUIRE(fs::client::is_data_object(conn, data_object));

    // Create a test user.
    const adm::user alice{"test_user_alice"};
    REQUIRE(adm::client::add_user(conn, alice).value() == 0);

    irods::at_scope_exit remove_test_user{
        [&conn, &alice] { REQUIRE(adm::client::remove_user(conn, alice).value() == 0); }};

    // Become the test user.
    auto* conn_ptr = static_cast<RcComm*>(conn);
    REQUIRE(rc_switch_user(conn_ptr, alice.name.c_str(), alice.zone.c_str()) == 0);
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    CHECK(conn_ptr->clientUser.userName == alice.name);
    CHECK(conn_ptr->clientUser.rodsZone == alice.zone);
    CHECK(std::strcmp(conn_ptr->clientUser.userType, adm::to_c_str(adm::user_type::rodsuser)) == 0);
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    CHECK(conn_ptr->clientUser.authInfo.authFlag == LOCAL_USER_AUTH);

    // Show that the test user cannot see the administrator's collection or data object.
    CHECK_FALSE(fs::client::exists(conn, sandbox));
    CHECK_FALSE(fs::client::exists(conn, data_object));

    // Become the administrator so that the test can clean up properly.
    REQUIRE(rc_switch_user(conn_ptr, env.rodsUserName, env.rodsZone) == 0);
    CHECK(std::strcmp(conn_ptr->clientUser.userName, env.rodsUserName) == 0);
    CHECK(std::strcmp(conn_ptr->clientUser.rodsZone, env.rodsZone) == 0);
    CHECK(std::strcmp(conn_ptr->clientUser.userType, adm::to_c_str(adm::user_type::rodsadmin)) == 0);
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    CHECK(conn_ptr->clientUser.authInfo.authFlag == LOCAL_PRIV_USER_AUTH);
}

