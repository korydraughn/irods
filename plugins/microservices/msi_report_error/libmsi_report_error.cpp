/// \file

#include "irods_ms_plugin.hpp"
#include "irods_re_structs.hpp"
#include "msParam.h"
#include "rcMisc.h"
#include "rodsErrorTable.h"
#include "irods_error.hpp"
#include "irods_logger.hpp"

#include <functional>
#include <string>
#include <exception>

namespace
{
    using log = irods::experimental::log;

    auto to_string(msParam_t& _p) -> const char*
    {
        const auto* s = parseMspForStr(&_p);

        if (!s) {
            THROW(SYS_INVALID_INPUT_PARAM, "Failed to convert microservice argument to string.");
        }

        return s;
    }

    auto msi_impl(msParam_t* _error_message, ruleExecInfo_t* _rei) -> int
    {
        if (!_error_message) {
            log::microservice::error("Invalid error message argument.");
            return SYS_INVALID_INPUT_PARAM;
        }

        try {
            addRErrorMsg(&_rei->rsComm->rError, STDOUT_STATUS, to_string(*_error_message));
            return 0;
        }
        catch (const irods::exception& e) {
            log::microservice::error(e.what());
            return e.code();
        }
        catch (const std::exception& e) {
            log::microservice::error(e.what());
            return SYS_INTERNAL_ERR;
        }
        catch (...) {
            log::microservice::error("An unknown error occurred while processing the request.");
            return SYS_UNKNOWN_ERROR;
        }
    }

    template <typename... Args, typename Function>
    auto make_msi(const std::string& _name, Function _func) -> irods::ms_table_entry*
    {
        auto* msi = new irods::ms_table_entry{sizeof...(Args)};
        msi->add_operation<Args..., ruleExecInfo_t*>(_name, std::function<int(Args..., ruleExecInfo_t*)>(_func));
        return msi;
    }
} // anonymous namespace

extern "C"
auto plugin_factory() -> irods::ms_table_entry*
{
    return make_msi<msParam_t*>("msi_report_error", msi_impl);
}

#ifdef IRODS_FOR_DOXYGEN
/// Reports error information to the client by adding an error message to the
/// rError object in the communication object (i.e. RsComm).
///
/// \param[in] _error_message The error message to add.
/// \param[in,out] _rei       A ::RuleExecInfo object that is automatically handled
///                           by the rule engine plugin framework. Users must ignore
///                           this parameter.
///
/// \return An integer.
/// \retval 0        On success.
/// \retval Non-zero On failure.
///
/// \since 4.2.9
auto msi_report_error(msParam_t* _error_message, ruleExecInfo_t* _rei) -> int;
#endif // IRODS_FOR_DOXYGEN

