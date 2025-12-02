#include "irods/reAction.hpp"

#include "irods/irods_ms_plugin.hpp"
#include "irods/rodsErrorTable.h"

namespace
{
} // namespace

irods::ms_table& get_microservice_table() {
    static irods::ms_table micros_table;
    return micros_table;
}

int msi_rodsadmin_mode_begin(ruleExecInfo_t* rei)
{
    if (!rei || !rei->rsComm) {
        return INVALID_INPUT_ARGUMENT_NULL_POINTER;
    }

    // TODO Materialize a RsComm which represents the local rodsadmin.
    // Things to consider:
    // - server redirects and identity propagation

    return 0;
}

int msi_rodsadmin_mode_end(ruleExecInfo_t* rei)
{
    if (!rei || !rei->rsComm) {
        return INVALID_INPUT_ARGUMENT_NULL_POINTER;
    }

    // TODO Deactivate the RsComm if it exists.

    return 0;
}
