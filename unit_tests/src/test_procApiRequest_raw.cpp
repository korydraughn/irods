#include <catch2/catch_all.hpp>

#include "irods/apiNumber.h"
#include "irods/client_connection.hpp"
#include "irods/packStruct.h"
#include "irods/procApiRequest.h"
#include "irods/rodsClient.h"
#include "irods/rodsErrorTable.h"

#include <algorithm>
#include <array>
#include <cstring>

// NO LINTNEXTLINE(readability-function-cognitive-complexity)
TEST_CASE("procApiRequest_raw allows overriding packing instructions")
{
    load_client_api_plugins();

    struct api_output {
        int serverType;             // RCAT_ENABLED or RCAT_NOT_ENABLED
        uint serverBootTime;
        char relVersion[NAME_LEN];  // Release version number
        char apiVersion[NAME_LEN];  // API version number
        char rodsZone[NAME_LEN];    // Zone of this server
        bytesBuf_t certinfo;
    };

    constexpr const char* pi_name = "api_output_PI";
    constexpr const char* pi_instruction =
        "int serverType; "
        "int serverBootTime; "
        "str relVersion[NAME_LEN]; "
        "str apiVersion[NAME_LEN]; "
        "str rodsZone[NAME_LEN]; "
        "struct BinBytesBuf_PI;";

    const auto pi_table = std::to_array<PackingInstruction>({
        {pi_name, pi_instruction, nullptr},
        {PACK_TABLE_END_PI, nullptr, nullptr}
    });

    api_output output{};

    irods::experimental::client_connection conn;

    const auto ec = procApiRequest_raw(
        static_cast<RcComm*>(conn), // conn
        GET_MISC_SVR_INFO_AN, // api number
        pi_table.data(), // pi table
        nullptr, // input pi
        nullptr, // input data struct
        nullptr, // input bs
        pi_name, // output pi
        static_cast<void**>(static_cast<void*>(&output)), // output data struct
        nullptr // output bs
    );
    REQUIRE(ec == 0);
}
