#include "irods/procLog.h"

#include "irods/irods_server_properties.hpp"
#include "irods/irods_logger.hpp"

#include <boost/lexical_cast.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

int readProcLog(int pid, procLog_t* procLog)
{
    using log_api = irods::experimental::log::api;

    if (nullptr == procLog) {
        log_api::error("{}: Invalid input argument: nullptr", __func__);
        return USER__NULL_INPUT_ERR;
    }

    const std::filesystem::path ips_data_dir = irods::get_server_property<std::string>("ips_data_directory");
    const auto agent_info_path = ips_data_dir / std::to_string(pid);

    std::ifstream procStream{agent_info_path};
    std::vector<std::string> procTokens;
    while (!procStream.eof() && procTokens.size() < 7) {
        std::string token;
        procStream >> token;
        log_api::debug("{}: Adding token to agent proc info: [{}]", __func__, token);
        procTokens.push_back(std::move(token));
    }

    if (procTokens.size() != 7) {
        log_api::error("{}: Agent process info: [{}], number of parameters: [{}]", __func__, agent_info_path.c_str(), procTokens.size());
        return UNIX_FILE_READ_ERR;
    }

    procLog->pid = pid;

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    std::snprintf(procLog->clientName, sizeof(procLog->clientName), "%s", procTokens[0].c_str());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    std::snprintf(procLog->clientZone, sizeof(procLog->clientZone), "%s", procTokens[1].c_str());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    std::snprintf(procLog->proxyName, sizeof(procLog->proxyName), "%s", procTokens[2].c_str());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    std::snprintf(procLog->proxyZone, sizeof(procLog->proxyZone), "%s", procTokens[3].c_str());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    std::snprintf(procLog->progName, sizeof(procLog->progName), "%s", procTokens[4].c_str());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    std::snprintf(procLog->remoteAddr, sizeof(procLog->remoteAddr), "%s", procTokens[5].c_str());

    try {
        procLog->startTime = boost::lexical_cast<unsigned int>(procTokens[6].c_str());
    }
    catch (const std::exception& e) {
        log_api::error("{}: Could not convert [{}] to unsigned int.", __func__, procTokens[6]);
        return INVALID_LEXICAL_CAST;
    }

    return 0;
} // readProcLog
