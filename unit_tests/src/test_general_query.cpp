#include "catch.hpp"

#include "client_connection.hpp"
#include "dstream.hpp"
#include "filesystem.hpp"
#include "irods_at_scope_exit.hpp"
#include "genQuery.h"
#include "rcMisc.h"
#include "rodsClient.h"
#include "rodsGenQuery.h"
#include "transport/default_transport.hpp"

#include <fmt/format.h>

#include <string>
#include <string_view>

namespace fs = irods::experimental::filesystem;
namespace io = irods::experimental::io;

TEST_CASE("general query")
{
    load_client_api_plugins();

    rodsEnv env;
    _getRodsEnv(env);

    const auto sandbox = fs::path{env.rodsHome} / "unit_testing_sandbox";
    irods::experimental::client_connection conn;

    if (!fs::client::exists(conn, sandbox)) {
        REQUIRE(fs::client::create_collection(conn, sandbox));
    }

    irods::at_scope_exit remove_sandbox{[&conn, &sandbox] {
        REQUIRE(fs::client::remove_all(conn, sandbox, fs::remove_options::no_trash));
    }};

    SECTION("embedded single quotes are supported")
    {
        const auto path = sandbox / "data'_obj''ect.txt";

        {
            io::client::native_transport tp{conn};
            io::odstream stream{tp, path};
        }

        REQUIRE(fs::client::exists(conn, path));

        // Run the query.

        GenQueryInp gq_input{};
        irods::at_scope_exit clear_gq_input{[&gq_input] { clearGenQueryInp(&gq_input); }};

        addInxIval(&gq_input.selectInp, COL_COLL_NAME, 1);
        addInxIval(&gq_input.selectInp, COL_DATA_NAME, 1);

        addInxVal(&gq_input.sqlCondInp, COL_COLL_NAME, fmt::format("= '{}'", sandbox.c_str()).data());
        addInxVal(&gq_input.sqlCondInp, COL_DATA_NAME, "= 'data'_obj''ect.txt'");

        gq_input.maxRows = MAX_SQL_ROWS;

        GenQueryOut* gq_output{};
        irods::at_scope_exit clear_gq_output{[&gq_output] { freeGenQueryOut(&gq_output); }};

        REQUIRE(rcGenQuery(static_cast<RcComm*>(conn), &gq_input, &gq_output) >= 0);

        // Check the results.

        using namespace std::string_view_literals;

        REQUIRE(1 == gq_output->rowCnt);
        REQUIRE(path.parent_path() == &gq_output->sqlResult[0].value[0]);
        REQUIRE(path.object_name() == &gq_output->sqlResult[1].value[0]);
    }
}

