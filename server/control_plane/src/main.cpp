#include "irods/client_connection.hpp"
#include "irods/irods_buffer_encryption.hpp"
#include "irods/irods_exception.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_lookup_table.hpp"
#include "irods/irods_query.hpp"
#include "irods/irods_resource_manager.hpp"
#include "irods/irods_server_control_plane.hpp"
#include "irods/irods_server_properties.hpp"
//#include "irods/irods_server_state.hpp"
#include "irods/irods_stacktrace.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/rcMisc.h"
//#include "irods/rodsServer.hpp"
#include "irods/server_utilities.hpp"
#include "irods/sockComm.h"

#include <avro/Encoder.hh>
#include <avro/Decoder.hh>
#include <avro/Specific.hh>

#include <boost/lexical_cast.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include <unistd.h>
#include <sys/types.h>

#include <csignal>
#include <cstdio>
#include <cstddef> // For std::size_t
#include <ctime>
#include <string>
#include <functional>
#include <unordered_map>
#include <algorithm>
#include <optional>

// clang-format off
using handler_type   = std::function<error(const std::string&, const std::size_t, std::string&)>;
using host_list_type = std::vector<std::string>;
using log            = irods::experimental::log::server;
// clang-format on

struct control_plane_context
{
    std::unordered_map<std::string, handler_type> handlers;
    std::string port_property;
    std::string local_server_hostname;
    std::string provider_hostname;
}; // struct control_plane_context

int ctrl_plane_signal_ = 0;

void ctrl_plane_handle_shutdown_signal(int sig)
{
    ctrl_plane_signal_ = SIGTERM;
}

void ctrl_plane_sleep(int _s, int _ms)
{
    useconds_t us = (_s * 1000000) + (_ms * 1000);
    usleep(us);
}

void resolve_hostnames_using_server_config(std::vector<std::string>& _hostnames)
{
    std::transform(std::begin(_hostnames), std::end(_hostnames), std::begin(_hostnames),
        [](std::string& _hostname) {
            return resolve_hostname(_hostname, hostname_resolution_scheme::match_preferred)
                .value_or(_hostname);
        });
}

irods::error forward_server_control_command(
    const std::string& _name,
    const std::string& _host,
    const std::string& _port_keyword,
    std::string& _output)
{
    if (EMPTY_RESC_HOST == _host) {
        return SUCCESS();
    }

    const int time_out, port, num_hash_rounds;
    std::optional<std::string> encryption_algorithm;
    buffer_crypt::array_t shared_secret;
    try {
        const auto& config = server_properties::instance().map();
        time_out = config.at(CFG_SERVER_CONTROL_PLANE_TIMEOUT).get<int>();
        port = config.at(_port_keyword).get<int>();
        num_hash_rounds = config.at(CFG_SERVER_CONTROL_PLANE_ENCRYPTION_NUM_HASH_ROUNDS_KW).get<int>();
        encryption_algorithm.reset(config.at(CFG_SERVER_CONTROL_PLANE_ENCRYPTION_ALGORITHM_KW).get_ref<const std::string&>());
        const auto& key = config.at(CFG_SERVER_CONTROL_PLANE_KEY).get_ref<const std::string&>();
        shared_secret.assign(key.begin(), key.end());
    }
    catch (const nlohmann::json::exception& e) {
        return ERROR(SYS_CONFIG_FILE_ERR, fmt::format("Control plane configuration error: {}", e.what()));
    }

    // standard zmq rep-req communication pattern
    zmq::context_t zmq_ctx(1);
    zmq::socket_t zmq_skt(zmq_ctx, ZMQ_REQ);
    zmq_skt.set(zmq::sockopt::rcvtimeo, time_out);
    zmq_skt.set(zmq::sockopt::sndtimeo, time_out);
    zmq_skt.set(zmq::sockopt::linger, 0);

    // this is the client so we connect rather than bind
    const auto conn_str = fmt::format("tcp://{}:{}", _host, port);

    try {
        zmq_skt.connect( conn_str.c_str() );
    }
    catch (const zmq::error_t&) {
        _output += "{\n    \"failed_to_connect\" : \"" + conn_str + "\"\n},\n";
        return ERROR(SYS_INVALID_INPUT_PARAM, _output);
    }


    // build the command to forward
    control_plane_command cmd;
    cmd.command = _name;
    cmd.options[irods::SERVER_CONTROL_OPTION_KW] = SERVER_CONTROL_HOSTS_OPT;
    cmd.options[irods::SERVER_CONTROL_HOST_KW] = _host;

    // serialize using the generated avro class
    auto out = avro::memoryOutputStream();
    avro::EncoderPtr e = avro::binaryEncoder();
    e->init(*out);
    avro::encode(*e, cmd);
    std::shared_ptr<std::vector<std::uint8_t>> data = avro::snapshot(*out);

    buffer_crypt crypt(
        shared_secret.size(),  // key size
        0,                     // salt size ( we dont send a salt )
        num_hash_rounds,       // num hash rounds
        encryption_algorithm->c_str() );

    buffer_crypt::array_t iv;
    buffer_crypt::array_t data_to_send;
    buffer_crypt::array_t data_to_encrypt(data->data(), data->data() + data->size());
    if (irods::error ret = crypt.encrypt(shared_secret, iv, data_to_encrypt, data_to_send); !ret.ok()) {
        return PASS(ret);
    }

    // copy binary encoding into a zmq message for transport
    zmq::message_t rep(data_to_send.size());
    std::memcpy(rep.data(), data_to_send.data(), data_to_send.size());
    zmq_skt.send(rep, zmq::send_flags::none);

    // wait for the server response
    zmq::message_t req;
    { [[maybe_unused]] const auto ec = zmq_skt.recv(req); }

    if (0 == req.size()) {
        _output += "{\n    \"response_message_is_empty_from\" : \"" + conn_str + "\"\n},\n";
        return ERROR(SYS_INVALID_INPUT_PARAM, "empty response string");
    }

    // decrypt the message before passing to avro
    buffer_crypt::array_t data_to_process;
    const std::uint8_t* data_ptr = static_cast<const std::uint8_t*>(req.data());
    buffer_crypt::array_t data_to_decrypt(data_ptr, data_ptr + req.size());
    ret = crypt.decrypt(shared_secret, iv, data_to_decrypt, data_to_process);
    if (!ret.ok()) {
        irods::log(PASS(ret));
        _output += "{\n    \"failed_to_decrpyt_message_from\" : \"" + conn_str + "\"\n},\n";
        log::error("Failed to decrpyt [{}]", req.data());
        return PASS(ret);
    }

    std::string rep_str(reinterpret_cast<char*>(data_to_process.data()), data_to_process.size());
    if (irods::SERVER_CONTROL_SUCCESS != rep_str) {
        // check if the result is really an error or a status
        if (std::string::npos == rep_str.find("[-]")) {
            _output += rep_str;
        }
        else {
            _output += "{\n    \"invalid_message_format_from\" : \"" + conn_str + "\"\n},\n";
            return ERROR(CONTROL_PLANE_MESSAGE_ERROR, rep_str);
        }
    }

    return SUCCESS();
} // forward_server_control_command

void kill_delay_server()
{
    if (const auto pid = irods::get_pid_from_file(irods::PID_FILENAME_DELAY_SERVER); pid) {
        log::debug("[{}:{}] - Sending kill signal to delay server.", __func__, __LINE__);

        // Previously, we ran kill_pid.py here.
        // This would send three signals to the process, one right after the other:
        // SIGSTOP (suspend), SIGTERM (terminate), then SIGKILL (kill)
        // SIGSTOP is omitted here as it would prevent any signal handlers from running.
        // SIGKILL does as well, but we currently lack handling for cases in which
        // a SIGTERM signal handler fails to end the process.

        kill(*pid, SIGTERM);
        kill(*pid, SIGKILL);
    }
} // kill_delay_server

irods::error server_operation_shutdown(
    const std::string& _wait_option,
    const std::size_t _wait_seconds,
    std::string& _output)
{
    rodsEnv env;
    _reloadRodsEnv(env);
    _output += "{\n    \"shutting down\": \"";
    _output += env.rodsHost;
    _output += "\"\n},\n";

    int sleep_time_out_milli_sec = 0;
    try {
        sleep_time_out_milli_sec = get_server_property<int>(CFG_SERVER_CONTROL_PLANE_TIMEOUT);
    }
    catch (const irods::exception& e) {
        return irods::error(e);
    }

    if (irods::SERVER_CONTROL_FORCE_AFTER_KW == _wait_option) {
        // Convert seconds to milliseconds for comparison.
        sleep_time_out_milli_sec = _wait_seconds * 1000;
    }

    int wait_milliseconds = irods::SERVER_CONTROL_POLLING_TIME_MILLI_SEC;

    server_state& svr_state = server_state::instance();
    svr_state(server_state::PAUSED);

    int sleep_time = 0;
    bool timeout_flg = false;
    int proc_cnt = getAgentProcCnt();

    kill_delay_server();

    while (proc_cnt > 0 && !timeout_flg) {
        // takes sec, millisec
        ctrl_plane_sleep(0, wait_milliseconds);

        if (SERVER_CONTROL_WAIT_FOREVER_KW != _wait_option) {
            sleep_time += SERVER_CONTROL_POLLING_TIME_MILLI_SEC;
            if (sleep_time > sleep_time_out_milli_sec) {
                timeout_flg = true;
            }
        }

        proc_cnt = getAgentProcCnt();
    }

    // actually shut down the server
    svr_state(server_state::STOPPED);

    // block until server exits to return
    while (!timeout_flg) {
        // takes sec, millisec
        ctrl_plane_sleep(0, wait_milliseconds);

        sleep_time += SERVER_CONTROL_POLLING_TIME_MILLI_SEC;
        if (sleep_time > sleep_time_out_milli_sec) {
            timeout_flg = true;
        }

        std::string the_server_state = svr_state();
        if (irods::server_state::EXITED == the_server_state) {
            break;
        }
    }

    return SUCCESS();
} // server_operation_shutdown

irods::error rule_engine_operation_shutdown(
    const std::string&, // _wait_option,
    const std::size_t,       // _wait_seconds,
    std::string& _output)
{
    rodsEnv env;
    _reloadRodsEnv(env);
    _output += "{\n    \"shutting down\": \"";
    _output += env.rodsHost;
    _output += "\"\n},\n";

    server_state& s = server_state::instance();
    s(server_state::STOPPED);
    return SUCCESS();
} // rule_engine_server_operation_shutdown

irods::error operation_pause(
    const std::string&, // _wait_option,
    const std::size_t,       // _wait_seconds,
    std::string& _output)
{
    rodsEnv env;
    _reloadRodsEnv(env);
    _output += "{\n    \"pausing\": \"";
    _output += env.rodsHost;
    _output += "\"\n},\n";
    server_state& s = server_state::instance();
    s( server_state::PAUSED );

    return SUCCESS();
} // operation_pause

irods::error operation_resume(
    const std::string&, // _wait_option,
    const std::size_t,       // _wait_seconds,
    std::string& _output)
{
    rodsEnv env;
    _reloadRodsEnv(env);
    _output += "{\n    \"resuming\": \"";
    _output += env.rodsHost;
    _output += "\"\n},\n";

    server_state& s = server_state::instance();
    s( server_state::RUNNING );
    return SUCCESS();
} // operation_resume

int get_pid_age(pid_t _pid)
{
    std::vector<std::string> args{std::to_string(_pid)};

    std::string pid_age;
    irods::error ret = get_script_output_single_line("python3", "pid_age.py", args, pid_age);
    if (!ret.ok()) {
        irods::log(PASS(ret));
        return 0;
    }

    double age = 0.0;
    try {
        age = boost::lexical_cast<double>(pid_age);
    }
    catch (const boost::bad_lexical_cast&) {
        log::error("get_pid_age bad lexical cast for [{}]", pid_age);
    }

    return static_cast<int>(age);
} // get_pid_age

irods::error operation_status(
    const std::string&, // _wait_option,
    const std::size_t,       // _wait_seconds,
    std::string& _output)
{
    rodsEnv env;
    _reloadRodsEnv(env);

    using json = nlohmann::json;

    json obj{
        {"hostname", env.rodsHost},
        {"irods_server_pid", getpid()},
        {"re_server_pid", irods::get_pid_from_file(irods::PID_FILENAME_DELAY_SERVER).value_or(0)}
    };

    server_state& s = server_state::instance();
    obj["status"] = s();

    auto arr = json::array();

    std::vector<int> pids;
    getAgentProcPIDs( pids );
    for (std::size_t i = 0; i < pids.size(); ++i) {
        int pid = pids[i];
        int age = get_pid_age(pids[i]);

        arr.push_back(json::object({
            {"agent_pid", pid},
            {"age", age}
        }));
    }

    obj["agents"] = arr;

    _output += obj.dump(4);
    _output += ",";

    return SUCCESS();
} // operation_status

irods::error operation_ping(
    const std::string&, // _wait_option,
    const std::size_t,       // _wait_seconds,
    std::string& _output)
{
    _output += "{\n    \"status\": \"alive\"\n},\n";
    /*rodsEnv env;
    _reloadRodsEnv( env );
    _output += "{\n    \"pinging\": \"";
    _output += env.rodsHost;
    _output += "\"\n},\n";*/
    return SUCCESS();
}

bool is_host_in_list(const std::string& _hn, const host_list_type& _hosts)
{
    const auto e = std::end(_hosts);

    return e != std::find_if(std::begin(_hosts), e, [&_hn](const std::string& _hostname) {
        return _hostname == _hn;
    });
} // is_host_in_list

control_plane_context init_control_plane_context(const std::string& _prop)
{
    if (_prop_.empty()) {
        THROW(SYS_INVALID_INPUT_PARAM, "control_plane_port key is empty");
    }

    control_plane_context context;

    // clang-format off
    context.handlers[irods::SERVER_CONTROL_PAUSE]  = operation_pause;
    context.handlers[irods::SERVER_CONTROL_RESUME] = operation_resume;
    context.handlers[irods::SERVER_CONTROL_STATUS] = operation_status;
    context.handlers[irods::SERVER_CONTROL_PING]   = operation_ping;
    // clang-format on

    if (_prop == irods::CFG_RULE_ENGINE_CONTROL_PLANE_PORT) {
        context.handlers[irods::SERVER_CONTROL_SHUTDOWN] = rule_engine_operation_shutdown;
    }
    else {
        context.handlers[irods::SERVER_CONTROL_SHUTDOWN] = server_operation_shutdown;
    }

    // Get the local server's hostname for ordering.
    rodsEnv env;
    _reloadRodsEnv(env);
    context.local_server_hostname = env.rodsHost;

    // Get the provider's hostname for ordering.
    context.provider_hostname = server_properties::instance().map()
        .at(irods::CFG_CATALOG_PROVIDER_HOSTS_KW)[0].get_ref<const std::string&>();

    // Repave provider's hostname as we do not want to process "localhost".
    if ("localhost" == context.provider_hostname) {
        context.provider_hostname = context.local_server_hostname;
        log::error("Provider's hostname is localhost, not a FQDN.");
        // TODO :: throw fancy exception here when we disallow localhost
    }

    return context;
} // ctor

irods::error forward_command(const control_plane_context& _context,
                             const std::string& _name,
                             const std::string& _host,
                             const std::string& _port_keyword,
                             const std::string& _wait_option,
                             const std::size_t& _wait_seconds,
                             std::string& _output)
{
    // if this is forwarded to us, just perform the operation
    if (_host == _context.local_server_hostname) {
        return process_host_list(_name, _wait_option, _wait_seconds, {_host}, _output);
    }

    return forward_server_control_command(_name, _host, _port_keyword, _output);
} // forward_command

irods::error get_resource_host_names(host_list_type& _host_names)
{
#if 1
    try {
        irods::experimental::client_connection conn;

        for (auto& row : irods::query{static_cast<RcComm*>(conn), "select RESC_LOC"}) {
            if ("localhost" != row[0]) {
                _host_names.push_back(std::move(row[0]));
            }
        }

        return SUCCESS();
    }
    catch (const irods::exception& e) {
        return ERROR(e.code(), e.what());
    }
    catch (const std::exception& e) {
        return ERROR(SYS_LIBRARY_ERROR, e.what());
    }
    catch (...) {
        return ERROR(SYS_UNKNOWN_ERROR, "Control plane encountered unknown error");
    }
#else
    rodsEnv env;
    _reloadRodsEnv(env);
    rcComm_t* comm = rcConnect(
                         env.rodsHost,
                         env.rodsPort,
                         env.rodsUserName,
                         env.rodsZone,
                         NO_RECONN, 0 );
    if ( !comm ) {
        return ERROR(NULL_VALUE_ERR, "rcConnect failed");
    }

    int status = clientLogin(comm, 0, env.rodsAuthScheme);
    if ( status != 0 ) {
        rcDisconnect( comm );
        return ERROR(status, "client login failed");
    }

    genQueryInp_t  gen_inp;
    genQueryOut_t* gen_out = NULL;
    memset( &gen_inp, 0, sizeof( gen_inp ) );

    addInxIval( &gen_inp.selectInp, COL_R_LOC, 1 );
    gen_inp.maxRows = MAX_SQL_ROWS;

    int cont_idx = 1;
    while ( cont_idx ) {
        int status = rcGenQuery(comm, &gen_inp, &gen_out);
        if ( status < 0 ) {
            rcDisconnect( comm );
            freeGenQueryOut( &gen_out );
            clearGenQueryInp( &gen_inp );
            return ERROR(status, "genQuery failed.");

        } // if

        sqlResult_t* resc_loc = getSqlResultByInx(gen_out, COL_R_LOC);
        if ( !resc_loc ) {
            rcDisconnect( comm );
            freeGenQueryOut( &gen_out );
            clearGenQueryInp( &gen_inp );
            return ERROR(UNMATCHED_KEY_OR_INDEX, "getSqlResultByInx for COL_R_LOC failed");
        }

        for ( int i = 0; i < gen_out->rowCnt; ++i ) {
            const std::string hn(&resc_loc->value[resc_loc->len * i]);
            if ("localhost" != hn) {
                _host_names.push_back(hn);
            }
        }

        cont_idx = gen_out->continueInx;
    }

    freeGenQueryOut( &gen_out );
    clearGenQueryInp( &gen_inp );

    status = rcDisconnect( comm );
    if ( status < 0 ) {
        return ERROR(status, "failed in rcDisconnect");
    }

    return SUCCESS();
#endif
} // get_resource_host_names

irods::error notify_provider_and_local_servers_preop(const control_plane_context& _context,
                                                     const std::string& _cmd_name,
                                                     const std::string& _cmd_option,
                                                     const std::string& _wait_option,
                                                     const std::size_t& _wait_seconds,
                                                     const host_list_type& _cmd_hosts,
                                                     std::string& _output)
{
    if (irods::SERVER_CONTROL_RESUME != _cmd_name) {
        return SUCCESS();
    }

    irods::error ret = SUCCESS();
    const bool is_all_opt = (irods::SERVER_CONTROL_ALL_OPT == _cmd_option);
    const bool found_my_host = is_host_in_list(_context.local_server_hostname, _cmd_hosts);
    const bool found_provider_host = is_host_in_list(_context.provider_hostname, _cmd_hosts);
    const bool is_provider_host = (_context.local_server_hostname == _context.provider_hostname);

    // for pause or shutdown: pre-op forwards to the provider first,
    // then to itself, then others
    // for resume: we skip doing work here (we'll go last in post-op)
    if (found_provider_host || is_all_opt) {
        ret = forward_command(_cmd_name,
                              _context.provider_hostname,
                              irods::CFG_SERVER_CONTROL_PLANE_PORT,
                              _wait_option,
                              _wait_seconds,
                              _output);

        // takes sec, microsec
        ctrl_plane_sleep(0, irods::SERVER_CONTROL_FWD_SLEEP_TIME_MILLI_SEC);
    }

    // pre-op forwards to the local server second
    // such as for resume
    if (!is_provider_host && (found_my_host || is_all_opt)) {
        ret = forward_command(_cmd_name,
                              _context.local_server_hostname,
                              irods::CFG_SERVER_CONTROL_PLANE_PORT,
                              _wait_option,
                              _wait_seconds,
                              _output);
    }

    return ret;
} // notify_provider_and_local_servers_preop

irods::error notify_provider_and_local_servers_postop(const control_plane_context& _context,
                                                      const std::string& _cmd_name,
                                                      const std::string& _cmd_option,
                                                      const std::string& _wait_option,
                                                      const std::size_t& _wait_seconds,
                                                      const host_list_type& _cmd_hosts,
                                                      std::string& _output)
{
    irods::error ret = SUCCESS();
    if (irods::SERVER_CONTROL_RESUME == _cmd_name) {
        return SUCCESS();
    }

    bool is_all_opt = (irods::SERVER_CONTROL_ALL_OPT == _cmd_option);
    const bool found_my_host = is_host_in_list(_context.local_server_hostname, _cmd_hosts);
    const bool found_provider_host = is_host_in_list(_context.provider_hostname, _cmd_hosts);
    const bool is_provider_host = (_context.local_server_hostname == _context.provider_hostname);

    // post-op forwards to the local server first
    // then the provider such as for shutdown
    if (!is_provider_host && (found_my_host || is_all_opt)) {
        ret = forward_command(_cmd_name,
                              _context.local_server_hostname,
                              irods::CFG_SERVER_CONTROL_PLANE_PORT,
                              _wait_option,
                              _wait_seconds,
                              _output);
    }

    // post-op forwards to the provider last
    if (found_provider_host || is_all_opt) {
        ret = forward_command(_cmd_name,
                              _context.provider_hostname,
                              irods::CFG_SERVER_CONTROL_PLANE_PORT,
                              _wait_option,
                              _wait_seconds,
                              _output);
    }

    return ret;
} // notify_provider_and_local_servers_postop

irods::error validate_host_list(const control_plane_context& _context,
                                const host_list_type& _irods_hosts,
                                const host_list_type& _target_hosts,
                                host_list_type& _valid_hosts)
{
    for (auto&& target_host : _target_hosts) {
        // Return an error if the hostname does not match the hostname of a consumer or the provider.
        if (!is_host_in_list(target_host, _irods_hosts) && target_host != _context.provider_hostname) {
            return ERROR(SYS_INVALID_INPUT_PARAM, fmt::format("invalid server hostname [{}]", target_host));
        }

        // Skip the local server and provider because these are handled by server_operation_shutdown() directly.
        if (_context.provider_hostname == target_host || _context.local_server_hostname == target_host) {
            continue;
        }

        // Add the host to our newly ordered list.
        _valid_hosts.push_back(target_host);
    }

    return SUCCESS();
} // validate_host_list

irods::error extract_command_parameters(const control_plane_context& _context,
                                        const control_plane_command& _cmd,
                                        std::string& _name,
                                        std::string& _option,
                                        std::string& _wait_option,
                                        std::size_t& _wait_seconds,
                                        host_list_type& _hosts)
{
    // capture and validate the command parameter
    _name = _cmd.command;
    if (_context.handlers.count(_name) == 0) {
        return ERROR(SYS_INVALID_INPUT_PARAM, fmt::format("invalid command [{}]", _name));
    }

    // capture and validate the option parameter
    auto itr = _cmd.options.find(irods::SERVER_CONTROL_OPTION_KW);
    if (_cmd.options.end() == itr) {
        return ERROR(SYS_INVALID_INPUT_PARAM, "option parameter is empty");
    }

    _option = itr->second;
    if (irods::SERVER_CONTROL_ALL_OPT != _option && irods::SERVER_CONTROL_HOSTS_OPT != _option) {
        return ERROR(SYS_INVALID_INPUT_PARAM, fmt::format("invalid command option [{}]", _option));
    }

    // capture and validate the server hosts, skip the option key
    for (auto&& [k, v] : _cmd.options) {
        if (k == irods::SERVER_CONTROL_OPTION_KW) {
            continue;
        }
        else if (k == irods::SERVER_CONTROL_FORCE_AFTER_KW) {
            _wait_option = irods::SERVER_CONTROL_FORCE_AFTER_KW;
            _wait_seconds = boost::lexical_cast<std::size_t>(v);
        }
        else if (k == irods::SERVER_CONTROL_WAIT_FOREVER_KW) {
            _wait_option = irods::SERVER_CONTROL_WAIT_FOREVER_KW;
            _wait_seconds = 0;
        }
        else if (k.find(irods::SERVER_CONTROL_HOST_KW) != std::string::npos) {
            _hosts.push_back(v);
        }
        else {
            return ERROR(SYS_INVALID_INPUT_PARAM, fmt::format("invalid option key [{}]", k));
        }
    }

    return SUCCESS();
} // extract_command_parameters

irods::error process_host_list(const control_plane_context& _context,
                               const std::string& _cmd_name,
                               const std::string& _wait_option,
                               const std::size_t& _wait_seconds,
                               const host_list_type& _hosts,
                               std::string& _output)
{
    if (_hosts.empty()) {
        return SUCCESS();
    }

    irods::error fwd_err = SUCCESS();

    for (auto&& host : _hosts) {
        if ("localhost" == host) {
            continue;
        }

        std::string output;

        // We are the target server.
        if (host == _context.local_server_hostname) {
            irods::error ret = _context.handlers[_cmd_name](_wait_option, _wait_seconds, output);

            if (!ret.ok()) {
                fwd_err = PASS(ret);
            }

            _output += output;
        }
        // Forward to the correct server.
        else {
            irods::error ret = forward_command(_cmd_name,
                                               host,
                                               _context.port_property,
                                               _wait_option,
                                               _wait_seconds,
                                               output);

            if (!ret.ok()) {
                _output += output;
                log(PASS(ret));
                fwd_err = PASS(ret);
            }
            else {
                _output += output;
            }
        }
    }

    return fwd_err;
} // process_host_list

irods::error process_operation(const zmq::message_t& _msg, std::string& _output)
{
    control_plane_command cmd;

    irods::error ret = decrypt_incoming_command(_msg, cmd);
    if (!ret.ok()) {
        irods::log(PASS(ret));
        return PASS(ret);
    }

    std::string cmd_name;
    std::string cmd_option;
    std::string wait_option;
    host_list_type cmd_hosts;
    std::size_t wait_seconds = 0;

    ret = extract_command_parameters(cmd,
                                     cmd_name,
                                     cmd_option,
                                     wait_option,
                                     wait_seconds,
                                     cmd_hosts);
    if (!ret.ok()) {
        irods::log(PASS(ret));
        return PASS(ret);
    }

    ret = perform_operation(cmd_name,
                            cmd_option,
                            wait_option,
                            wait_seconds,
                            cmd_hosts,
                            _output);
    if (!ret.ok()) {
        irods::log(PASS(ret));
        return PASS(ret);
    }

    return SUCCESS();
} // process_operation

irods::error decrypt_incoming_command(const zmq::message_t& _msg, irods::control_plane_command& _cmd)
{
    if (_msg.size() <= 0) {
        return SUCCESS();
    }

    int num_hash_rounds;
    std::optional<std::string> encryption_algorithm;
    buffer_crypt::array_t shared_secret;
    try {
        const auto& config = server_properties::instance().map();
        num_hash_rounds = config.at(CFG_SERVER_CONTROL_PLANE_ENCRYPTION_NUM_HASH_ROUNDS_KW).get<int>();
        encryption_algorithm.reset(config.at(CFG_SERVER_CONTROL_PLANE_ENCRYPTION_ALGORITHM_KW).get_ref<const std::string&>());
        const auto& key = config.at(CFG_SERVER_CONTROL_PLANE_KEY).get_ref<const std::string&>();
        shared_secret.assign(key.begin(), key.end());
    }
    catch (const nlohmann::json::exception& e) {
        return ERROR(SYS_CONFIG_FILE_ERR, fmt::format("Control plane configuration error: {}", e.what()));
    }

    // decrypt the message before passing to avro
    buffer_crypt crypt(shared_secret.size(), // key size
                       0,                    // salt size ( we dont send a salt )
                       num_hash_rounds,      // num hash rounds
                       encryption_algorithm->c_str());

    buffer_crypt::array_t iv;
    buffer_crypt::array_t data_to_process;

    const auto* data_ptr = static_cast<const std::uint8_t*>(_msg.data());
    buffer_crypt::array_t data_to_decrypt(data_ptr, data_ptr + _msg.size());
    irods::error ret = crypt.decrypt(shared_secret, iv, data_to_decrypt, data_to_process);
    if (!ret.ok()) {
        irods::log(PASS(ret));
        return PASS(ret);
    }

    auto in = avro::memoryInputStream(static_cast<const std::uint8_t*>(data_to_process.data()), data_to_process.size());
    avro::DecoderPtr dec = avro::binaryDecoder();
    dec->init(*in);

    avro::decode(*dec, _cmd);

    return SUCCESS();
} // decrypt_incoming_command

irods::error perform_operation(const std::string& _cmd_name,
                               const std::string& _cmd_option,
                               const std::string& _wait_option,
                               const std::size_t& _wait_seconds,
                               const host_list_type& _cmd_hosts,
                               std::string& _output)
{
    irods::error final_ret = SUCCESS();
    host_list_type cmd_hosts = _cmd_hosts;

    // add safeguards - if server is paused only allow a resume call
    server_state& s = server_state::instance();
    std::string the_server_state = s();
    if (server_state::PAUSED == the_server_state && irods::SERVER_CONTROL_RESUME != _cmd_name) {
        _output = SERVER_PAUSED_ERROR;
        return SUCCESS();
    }

    resolve_hostnames_using_server_config(cmd_hosts);

    // the provider needs to be notified first in certain
    // cases such as RESUME where it is needed to capture
    // the host list for validation, etc
    auto ret = notify_provider_and_local_servers_preop(_cmd_name,
                                                       _cmd_option,
                                                       _wait_option,
                                                       _wait_seconds,
                                                       cmd_hosts,
                                                       _output);
    if (!ret.ok()) {
        final_ret = PASS(ret);
        log::error(final_ret.result());
    }

    host_list_type irods_hosts;
    ret = get_resource_host_names(irods_hosts);
    if (!ret.ok()) {
        final_ret = PASS(ret);
        log::error(final_ret.result());
    }

    if (irods::SERVER_CONTROL_ALL_OPT == _cmd_option) {
        cmd_hosts = irods_hosts;
    }

    host_list_type valid_hosts;
    ret = validate_host_list(irods_hosts, cmd_hosts, valid_hosts);
    if (!ret.ok()) {
        final_ret = PASS(ret);
        log::error(final_ret.result());
    }

    ret = process_host_list(_cmd_name, _wait_option, _wait_seconds, valid_hosts, _output);
    if (!ret.ok()) {
        final_ret = PASS(ret);
        log::error(final_ret.result());
    }

    // the provider needs to be notified last in certain
    // cases such as SHUTDOWN or PAUSE  where it is
    // needed to capture the host list for validation
    ret = notify_provider_and_local_servers_postop(_cmd_name,
                                                   _cmd_option,
                                                   _wait_option,
                                                   _wait_seconds,
                                                   cmd_hosts, // dont want sanitized
                                                   _output);
    if (!ret.ok()) {
        final_ret = PASS(ret);
        log::error(final_ret.result());
    }

    return final_ret;
} // process_operation

int main(int _argc, char* _argv[])
{
    // TODO The main server must fork the control plane with the socket file
    // descriptor passed as an argument. The socket descriptor is expected to
    // be one of the ends of a connected socket pair (UNIX Domain Socket).

    // TODO Argument needs to be defined in server_utilities.hpp.
    if (irods::create_pid_file(irods::PID_FILENAME_CONTROL_PLANE) != 0) {
        log::error("Could not create PID file for control plane.");
        return 1;
    }

    const auto context = init_control_plane_context(irods::CFG_SERVER_CONTROL_PLANE_PORT);

    signal(SIGINT, ctrl_plane_handle_shutdown_signal);
    signal(SIGHUP, ctrl_plane_handle_shutdown_signal);
    signal(SIGTERM, ctrl_plane_handle_shutdown_signal);

    int port;
    int num_hash_rounds;
    std::optional<std::string> encryption_algorithm;
    buffer_crypt::array_t shared_secret;
    try {
        const auto& config = server_properties::instance().map();
        port = config.at(context.port_property).get<int>();
        num_hash_rounds = config.at(CFG_SERVER_CONTROL_PLANE_ENCRYPTION_NUM_HASH_ROUNDS_KW).get<int>();
        encryption_algorithm.reset(config.at(CFG_SERVER_CONTROL_PLANE_ENCRYPTION_ALGORITHM_KW).get_ref<const std::string&>());
        const auto& key = config.at(CFG_SERVER_CONTROL_PLANE_KEY).get_ref<const std::string&>();
        shared_secret.assign(key.begin(), key.end());
    }
    catch (const nlohmann::json::exception& e) {
        log::error("Control plane configuration error: {}", e.what());
        return 1;
    }

    if (shared_secret.empty() ||
        encryption_algorithm->empty() ||
        0 == port ||
        0 == num_hash_rounds)
    {
        log::error("Control plane is not configured properly.");
        return 1;
    }

    while (true) {
        try {
            zmq::context_t zmq_ctx(1);
            zmq::socket_t zmq_skt(zmq_ctx, ZMQ_REP);

            const int time_out = irods::SERVER_CONTROL_POLLING_TIME_MILLI_SEC;
            zmq_skt.set(zmq::sockopt::rcvtimeo, time_out);
            zmq_skt.set(zmq::sockopt::sndtimeo, time_out);
            zmq_skt.set(zmq::sockopt::linger, 0);

            const auto conn_str = fmt::format("tcp://*:{}", port);
            zmq_skt.bind(conn_str.c_str());

            log::info(">>> control plane :: listening on port {}", port);

            server_state& s = server_state::instance();
            while (server_state::STOPPED != s() && server_state::EXITED != s()) {
                std::string output;

                switch (ctrl_plane_signal_) {
                    case 0: {
                        // Wait for a request.
                        zmq::message_t req;
                        { [[maybe_unused]] const auto ec = zmq_skt.recv(req); }
                        if (0 == req.size()) {
                            continue;
                        }

                        // Process the message.
                        std::string rep_msg = irods::SERVER_CONTROL_SUCCESS;
                        irods::error result = process_operation(req, output);

                        rep_msg = output;
                        if (!result.ok()) {
                            log(PASS(result));
                        }

#if 0
                        // TODO Investigate. This makes no sense.
                        if (!output.empty()) {
                            rep_msg = output;
                        }
#endif

                        buffer_crypt crypt(shared_secret.size(), // key size
                                           0,                    // salt size ( we dont send a salt )
                                           num_hash_rounds,      // num hash rounds
                                           encryption_algorithm->c_str());

                        buffer_crypt::array_t iv;
                        buffer_crypt::array_t data_to_send;
                        buffer_crypt::array_t data_to_encrypt(rep_msg.begin(), rep_msg.end());
                        if (const auto result = crypt.encrypt(shared_secret, iv, data_to_encrypt, data_to_send); !result.ok()) {
                            irods::log(PASS(result));
                        }

                        zmq::message_t rep(data_to_send.size());
                        std::memcpy(rep.data(), data_to_send.data(), data_to_send.size());
                        zmq_skt.send(rep, zmq::send_flags::none);

                        break;
                    }

                    case SIGINT:
                    case SIGTERM:
                    case SIGHUP:
                    {
#ifdef __GLIBC__
    #if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 32)
                        log::info(">>> control plane :: received signal SIG{}, performing shutdown operation ...",
                                  sigabbrev_np(ctrl_plane_signal_));
    #else
                        log::info(">>> control plane :: received signal {}, performing shutdown operation ...",
                                  sys_siglist[ctrl_plane_signal_]);
    #endif
#else
                        log::info(">>> control plane :: received signal ({}), performing shutdown operation ...",
                                  strsignal(ctrl_plane_signal_));
#endif
                        host_list_type cmd_hosts;
                        cmd_hosts.push_back(context.local_server_hostname);
                        const auto result = perform_operation(irods::SERVER_CONTROL_SHUTDOWN,
                                                              irods::SERVER_CONTROL_HOSTS_OPT,
                                                              "",
                                                              0,
                                                              cmd_hosts,
                                                              output);
                        if (!result.ok()) {
                            log(PASS(ret));
                        }

                        break;
                    }
                }
            }

            // Exited control loop normally, we're done.
            break;
        }
        catch (const zmq::error_t& e) {
            log::error("Caught ZMQ error: {}", e.what());
        }
        catch (const std::exception& e) {
            log::error("Caught exception: {}", e.what());
        }
        catch (...) {
            log::error("Caught unknown exception");
        }

        log::error("Restarting control plane.");
    }

    log::info("Control plane exited normally.");

    return 0;
}

