#include "irods_plugin_context.hpp"
#include "irods_re_plugin.hpp"
#include "irods_server_properties.hpp"
#include "irods_state_table.h"
#include "rodsDef.h"
#include "rodsError.h"
#include "rodsErrorTable.h"
#include "rodsLog.h"

#include "fmt/format.h"

#include <snappy-c.h>

#include <string>
#include <string_view>
#include <functional>
#include <vector>
#include <iterator>
#include <algorithm>
#include <array>

namespace
{
    constexpr std::array<std::string_view, 3> peps{
        "pep_api_data_obj_read_post",
        "pep_api_data_obj_read_pre",
        "pep_api_data_obj_write_pre"
    };

    irods::error rule_exists(irods::default_re_ctx&,
                             const std::string& rule_name,
                             bool& exists)
    {
        const auto end = std::end(peps);
        exists = std::find(std::begin(peps), end, rule_name) != end;
        return SUCCESS();
    }

    irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& rules)
    {
        rules.insert(std::end(rules), std::begin(peps), std::end(peps));
        return SUCCESS();
    }

    irods::error exec_rule(irods::default_re_ctx&,
                           const std::string& rule_name,
                           std::list<boost::any>& rule_arguments,
                           irods::callback effect_handler)
    {
        auto* bbuf = boost::any_cast<bytesBuf_t*>(*std::next(std::begin(rule_arguments), 3));
        auto* cbuf = static_cast<char*>(bbuf->buf);

        if ("pep_api_data_obj_read_pre" == rule_name) {
            rodsLog(LOG_NOTICE, "Original Buffer Length       = %d", bbuf->len);
            rodsLog(LOG_NOTICE, "Original Buffer Valid Ptr    = %s", (bbuf->buf ? "valid" : "not valid"));
        }
        else if ("pep_api_data_obj_read_post" == rule_name) {
            rodsLog(LOG_NOTICE, "Original Buffer Length       = %d", bbuf->len);

            // Compress the bytes read and store them in the output buffer.
            std::size_t output_length = snappy_max_compressed_length(bbuf->len);
            auto* output = static_cast<char*>(std::malloc(bbuf->len * sizeof(char)));
            rodsLog(LOG_NOTICE, "Max Compressed Buffer Length = %d", output_length);

            if (int ec = snappy_compress(cbuf, bbuf->len, output, &output_length); ec != SNAPPY_OK) {
                rodsLog(LOG_NOTICE, "Snappy compression error = %d", ec);
                return ERROR(FILE_READ_ERR, fmt::format("Snappy Compression Failed [{}]"));
            }

            rodsLog(LOG_NOTICE, "Compressed Buffer Length     = %d", output_length);

            if (output_length <= static_cast<std::size_t>(bbuf->len)) {
                rodsLog(LOG_NOTICE, "Updated read buffer");
                std::free(bbuf->buf);
                bbuf->buf = output;
                bbuf->len = output_length;
                return CODE(output_length);
            }

            return CODE(bbuf->len);
        }
        else if ("pep_api_data_obj_write_pre" == rule_name) {
            std::vector<char> src(bbuf->len);
            std::copy(cbuf, cbuf + bbuf->len, src.data());

            std::size_t output_length;
            snappy_uncompressed_length(cbuf, src.size(), &output_length);
            snappy_uncompress(src.data(), src.size(), cbuf, &output_length);

            rodsLog(LOG_NOTICE, "Original Buffer Lenth     = %d", bbuf->len);
            rodsLog(LOG_NOTICE, "Uncompressed Buffer Lenth = %d", output_length);
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    //
    // Rule Engine Plugin
    //

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;
} // anonymous namespace

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> pluggable_rule_engine*
{
    // clang-format off
    const auto no_op         = [](auto&&...) { return SUCCESS(); };
    const auto not_supported = [](auto&&...) { return CODE(SYS_NOT_SUPPORTED); };
    // clang-format on

    auto* re = new pluggable_rule_engine{_instance_name, _context};

    re->add_operation("start", operation<const std::string&>{no_op});
    re->add_operation("stop", operation<const std::string&>{no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});
    re->add_operation("exec_rule_text", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{not_supported});
    re->add_operation("exec_rule_expression", operation<const std::string&, msParamArray_t*, irods::callback>{not_supported});

    return re;
}

