#include "irods/irods_pack_table.hpp"
#include "irods/plugins/api/api_plugin_number.h"
#include "irods/client_api_allowlist.hpp"
#include "irods/fileDriver.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/json_deserialization.hpp"
#include "irods/rcConnect.h"
#include "irods/register_physical_path.h"
#include "irods/rodsDef.h"
#include "irods/rodsErrorTable.h"
#include "irods/rodsPackInstruct.h"

#include "irods/apiHandler.hpp"

#ifdef RODS_SERVER

#include "irods/apiHeaderAll.h"
#include "irods/collection.hpp"
#include "irods/dataObjOpr.hpp"
#include "irods/fileStat.h"
#include "irods/icatDefines.h"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_get_l1desc.hpp"
#include "irods/irods_hierarchy_parser.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_resource_backport.hpp"
#include "irods/irods_resource_redirect.hpp"
#include "irods/key_value_proxy.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/objMetaOpr.hpp"
#include "irods/phyPathReg.h"
#include "irods/physPath.hpp"
#include "irods/rcGlobalExtern.h"
#include "irods/rcMisc.h"
#include "irods/resource.hpp"
#include "irods/rodsLog.h"
#include "irods/rsCollCreate.hpp"
#include "irods/rsDataObjClose.hpp"
#include "irods/rsDataObjCreate.hpp"
#include "irods/rsFileClose.hpp"
#include "irods/rsFileClosedir.hpp"
#include "irods/rsFileMkdir.hpp"
#include "irods/rsFileOpen.hpp"
#include "irods/rsFileOpendir.hpp"
#include "irods/rsFileRead.hpp"
#include "irods/rsFileReaddir.hpp"
#include "irods/rsFileStat.hpp"
#include "irods/rsGlobalExtern.hpp"
#include "irods/rsModAccessControl.hpp"
#include "irods/rsModColl.hpp"
#include "irods/rsRegColl.hpp"
#include "irods/rsRegDataObj.hpp"
#include "irods/rsRegReplica.hpp"
#include "irods/rsSubStructFileStat.hpp"
#include "irods/rsSyncMountedColl.hpp"
#include "irods/server_utilities.hpp"
#include "irods/specColl.hpp"
#include "irods/stringOpr.h"
#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include "irods/filesystem.hpp"
#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "irods/replica_proxy.hpp"
#include <boost/lexical_cast.hpp>
#include <fmt/format.h>
#include <iostream>

/* holds a struct that describes pathname match patterns
   to exclude from registration. Needs to be global due
   to the recursive dirPathReg() calls. */
static pathnamePatterns_t *ExcludePatterns = NULL;

using log_api = irods::experimental::log::api;

namespace
{
    namespace ir = irods::experimental::replica;

    auto call_register_physical_path(
        irods::api_entry* _api,
        RsComm* _comm,
        DataObjInp* _in,
        BytesBuf** _out) -> int
    {
        return _api->call_handler<DataObjInp*, BytesBuf**>(_comm, _in, _out);
    } // call_register_physical_path

    pathnamePatterns_t* readPathnamePatternsFromFile(
        rsComm_t *_comm,
        const char *filename,
        const char* resc_hier)
    {
        int status;
        rodsStat_t *stbuf;
        fileStatInp_t fileStatInp;
        bytesBuf_t fileReadBuf;
        fileOpenInp_t fileOpenInp;
        fileReadInp_t fileReadInp;
        fileCloseInp_t fileCloseInp;
        int buf_len, fd;
        pathnamePatterns_t *pp;

        if ( _comm == NULL || filename == NULL || resc_hier == NULL ) {
            return NULL;
        }


        // =-=-=-=-=-=-=-
        // extract the host location from the resource hierarchy
        std::string location;
        irods::error ret = irods::get_loc_for_hier_string( resc_hier, location );
        if ( !ret.ok() ) {
            irods::log( PASSMSG( "readPathnamePatternsFromFile - failed in get_loc_for_hier_string", ret ) );
            return NULL;
        }

        memset( &fileStatInp, 0, sizeof( fileStatInp ) );
        rstrcpy( fileStatInp.fileName, filename, MAX_NAME_LEN );
        rstrcpy( fileStatInp.addr.hostAddr, location.c_str(), NAME_LEN );
        rstrcpy( fileStatInp.rescHier, resc_hier, MAX_NAME_LEN );
        status = rsFileStat( _comm, &fileStatInp, &stbuf );
        if ( status != 0 ) {
            if ( status != UNIX_FILE_STAT_ERR - ENOENT ) {
                log_api::debug(
                    "readPathnamePatternsFromFile: can't stat {}. status = {}", fileStatInp.fileName, status);
            }
            return NULL;
        }
        buf_len = stbuf->st_size;
        free( stbuf );

        memset( &fileOpenInp, 0, sizeof( fileOpenInp ) );
        rstrcpy( fileOpenInp.fileName, filename, MAX_NAME_LEN );
        rstrcpy( fileOpenInp.addr.hostAddr, location.c_str(), NAME_LEN );
        rstrcpy( fileOpenInp.resc_hier_, resc_hier, MAX_NAME_LEN );
        fileOpenInp.flags = O_RDONLY;
        fd = rsFileOpen( _comm, &fileOpenInp );
        if ( fd < 0 ) {
            log_api::info(
                "readPathnamePatternsFromFile: can't open {} for reading. status = {}", fileOpenInp.fileName, fd);
            return NULL;
        }

        memset( &fileReadBuf, 0, sizeof( fileReadBuf ) );
        fileReadBuf.buf = malloc( buf_len );
        if ( fileReadBuf.buf == NULL ) {
            log_api::info("readPathnamePatternsFromFile: could not malloc buffer");
            return NULL;
        }

        memset( &fileReadInp, 0, sizeof( fileReadInp ) );
        fileReadInp.fileInx = fd;
        fileReadInp.len = buf_len;
        status = rsFileRead( _comm, &fileReadInp, &fileReadBuf );

        memset( &fileCloseInp, 0, sizeof( fileCloseInp ) );
        fileCloseInp.fileInx = fd;
        rsFileClose( _comm, &fileCloseInp );

        if ( status < 0 ) {
            log_api::info("readPathnamePatternsFromFile: could not read {}. status = {}", fileOpenInp.fileName, status);
            free( fileReadBuf.buf );
            return NULL;
        }

        pp = readPathnamePatterns( ( char* )fileReadBuf.buf, buf_len );

        return pp;
    } // readPathnamePatternsFromFile

    int remotePhyPathReg(RsComm* _comm, DataObjInp* _inp, rodsServerHost* _host_info, BytesBuf** _out)
    {
        if (!_host_info) {
            log_api::error("remotePhyPathReg: Invalid host_info");
            return SYS_INVALID_SERVER_HOST;
        }

        if (const int ec = svrToSvrConnect(_comm, _host_info); ec < 0) {
            return ec;
        }

        char* out_str{};

        const int ec = rc_register_physical_path(_host_info->conn, _inp, &out_str);

        if (ec < 0) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}:{}] - rcPhyPathReg failed [path=[{}], ec=[{}]]",
                __FUNCTION__, __LINE__, _inp->objPath, ec));
        }

        freeBBuf(*_out);
        *_out = irods::to_bytes_buffer(out_str);
        std::free(out_str);
        out_str = nullptr;

        return ec;
    } // remotePhyPathReg

    int filePathRegRepl(
        RsComm* _comm,
        DataObjInp* _inp,
        const std::string_view _path,
        const std::string_view _resc,
        BytesBuf** _out)
    {
        namespace fs = irods::experimental::filesystem;

        auto phy_path_reg_cond_input = irods::experimental::make_key_value_proxy(_inp->condInput);

        // The resource hierarchy for this replica must be provided
        if (!phy_path_reg_cond_input.contains(RESC_HIER_STR_KW)) {
            log_api::info("{} - RESC_HIER_STR_KW is NULL", __FUNCTION__);
            return SYS_INVALID_INPUT_PARAM;
        }

        DataObjInfo* data_obj_info_head{};
        if (const int ec = getDataObjInfo(_comm, _inp, &data_obj_info_head, ACCESS_READ_OBJECT, 0); ec < 0) {
            log_api::error("{}: getDataObjInfo for [{}] failed", __FUNCTION__, _inp->objPath);
            return ec;
        }

        // Put a desired replica at the head of the list
        if (const int ec = sortObjInfoForOpen(&data_obj_info_head, phy_path_reg_cond_input.get(), 0 ); ec < 0) {
            // we did not match the hier string but we can still continue as we have a good copy for a read
            if (!data_obj_info_head) {
                return ec;
            }
        }

        // Free the structure before exiting the function
        irods::at_scope_exit free_data_obj_info_head{[&data_obj_info_head] { freeAllDataObjInfo(data_obj_info_head); }};

        // Populate information for the replica being registered
        auto dst_replica_info = *data_obj_info_head;
        irods::experimental::replica::replica_proxy destination_replica{dst_replica_info};
        destination_replica.physical_path(_path);
        destination_replica.resource(_resc);
        destination_replica.hierarchy(phy_path_reg_cond_input.at(RESC_HIER_STR_KW).value());

        // Set data_status to an empty string so that the replica status is not misleadingly labeled.
        destination_replica.status("{}");

        rodsLong_t resc_id{};
        if (const auto ret = resc_mgr.hier_to_leaf_id(destination_replica.hierarchy().data(), resc_id); !ret.ok()) {
            irods::log(PASS(ret));
        }
        destination_replica.resource_id(resc_id);

        // Prepare input for rsRegReplica
        regReplica_t reg_replica_input{};
        reg_replica_input.srcDataObjInfo = data_obj_info_head;
        reg_replica_input.destDataObjInfo = destination_replica.get();

        auto reg_replica_cond_input = irods::experimental::make_key_value_proxy(reg_replica_input.condInput);
        const auto free_cond_input = irods::at_scope_exit{[&reg_replica_input] { clearKeyVal(&reg_replica_input.condInput); }};

        // Carry privileged access keywords forward
        if (phy_path_reg_cond_input.contains(SU_CLIENT_USER_KW )) {
            reg_replica_cond_input[SU_CLIENT_USER_KW] = "";
            reg_replica_cond_input[ADMIN_KW] = "";
        }
        else if (phy_path_reg_cond_input.contains(ADMIN_KW)) {
            reg_replica_cond_input[ADMIN_KW] = "";
        }

        // Data size can be passed via DATA_SIZE_KW to save a stat later
        if (phy_path_reg_cond_input.contains(DATA_SIZE_KW)) {
            reg_replica_cond_input[DATA_SIZE_KW] = phy_path_reg_cond_input.at(DATA_SIZE_KW);
        }

        // Indicates whether data movement is expected
        if (phy_path_reg_cond_input.contains(REGISTER_AS_INTERMEDIATE_KW)) {
            destination_replica.replica_status(INTERMEDIATE_REPLICA);
            reg_replica_cond_input[REGISTER_AS_INTERMEDIATE_KW] = "";
        }

        // Registers the replica; bails on failure
        if (const int ec = rsRegReplica(_comm, &reg_replica_input); ec < 0) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}] - failed to register replica for [{}], status:[{}]",
                __FUNCTION__, destination_replica.logical_path(), ec));
            return ec;
        }

        const auto info_j = ir::to_json(destination_replica);
        freeBBuf(*_out);
        *_out = irods::to_bytes_buffer(info_j.dump());

        return 0;
    } // filePathRegRepl

    auto initDataObjInfoWithInp(dataObjInfo_t* dataObjInfo, dataObjInp_t* dataObjInp) -> int
    {
        namespace ix = irods::experimental;

        if (!dataObjInp || !dataObjInfo) {
            rodsLog(LOG_ERROR, "[%s] - null input", __FUNCTION__);
            return SYS_INTERNAL_NULL_INPUT_ERR;
        }
        auto kvp = ix::make_key_value_proxy(dataObjInp->condInput);
        memset(dataObjInfo, 0, sizeof(dataObjInfo_t));

        rstrcpy(dataObjInfo->objPath, dataObjInp->objPath, MAX_NAME_LEN);

        if (kvp.contains(DATA_ID_KW)) {
            dataObjInfo->dataId = std::atoll(kvp.at(DATA_ID_KW).value().data());
        }

        if (kvp.contains(RESC_NAME_KW)) {
            const auto resc_name = kvp.at(RESC_NAME_KW).value();
            rstrcpy(dataObjInfo->rescName, resc_name.data(), NAME_LEN);
            if (!kvp.contains(RESC_HIER_STR_KW)) {
                rstrcpy(dataObjInfo->rescHier, resc_name.data(), MAX_NAME_LEN);
            }
        }

        if (kvp.contains(RESC_HIER_STR_KW)) {
            auto hier = kvp.at(RESC_HIER_STR_KW).value();
            rstrcpy(dataObjInfo->rescHier, hier.data(), MAX_NAME_LEN);
        }

        irods::error ret = resc_mgr.hier_to_leaf_id(dataObjInfo->rescHier, dataObjInfo->rescId);
        if (!ret.ok()) {
            irods::log(PASS(ret));
        }

        snprintf(dataObjInfo->dataMode, SHORT_STR_LEN, "%d", dataObjInp->createMode);

        if (kvp.contains(DATA_TYPE_KW)) {
            auto data_type = kvp.at(DATA_TYPE_KW).value();
            rstrcpy(dataObjInfo->dataType, data_type.data(), NAME_LEN);
        }
        else {
            rstrcpy(dataObjInfo->dataType, "generic", NAME_LEN);
        }

        if (kvp.contains(FILE_PATH_KW)) {
            auto file_path = kvp.at(FILE_PATH_KW).value();
            rstrcpy(dataObjInfo->filePath, file_path.data(), MAX_NAME_LEN);
        }

        return 0;
    } // initDataObjInfoWithInp

    auto filePathReg(RsComm* _comm, DataObjInp* _inp, const std::string_view _resc, BytesBuf** _out) -> int
    {
        namespace fs = irods::experimental::filesystem;

        auto phy_path_reg_cond_input = irods::experimental::make_key_value_proxy(_inp->condInput);

        // The resource hierarchy for this replica must be provided
        if (!phy_path_reg_cond_input.contains(RESC_HIER_STR_KW)) {
            irods::log(LOG_NOTICE, fmt::format("[{}] - RESC_HIER_STR_KW is NULL", __FUNCTION__));
            return SYS_INVALID_INPUT_PARAM;
        }

        // Populate information for the replica being registered
        auto [destination_replica, destination_replica_lm] = irods::experimental::replica::make_replica_proxy();
        initDataObjInfoWithInp(destination_replica.get(), _inp );
        destination_replica.replica_status(GOOD_REPLICA);
        destination_replica.resource(_resc);
        destination_replica.hierarchy(phy_path_reg_cond_input.at(RESC_HIER_STR_KW).value());

        rodsLong_t resc_id{};
        if (const auto ret = resc_mgr.hier_to_leaf_id(destination_replica.hierarchy().data(), resc_id); !ret.ok()) {
            irods::log(PASS(ret));
        }
        destination_replica.resource_id(resc_id);

        if (!phy_path_reg_cond_input.contains(DATA_SIZE_KW) && destination_replica.size() <= 0) {
            const auto file_size = getFileMetadataFromVault(_comm, destination_replica.get());

            if (file_size < 0 && UNKNOWN_FILE_SZ != file_size) {
                irods::log(LOG_ERROR, fmt::format(
                     "[{}:{}] - getFileMetadataFromVault failed [path=[{}], ec=[{}]]",
                     __FUNCTION__, __LINE__, destination_replica.logical_path(), file_size));
                return file_size;
            }

            destination_replica.size(file_size);
        }
        else {
            std::string_view data_size_str = phy_path_reg_cond_input.at(DATA_SIZE_KW).value();

            try {
                destination_replica.size(boost::lexical_cast<rodsLong_t>(data_size_str));
            }
            catch (boost::bad_lexical_cast&) {
                irods::log(LOG_ERROR, fmt::format(
                    "[{}:{}] - bad_lexical_cast for dataSize, setting to 0 [path=[{}], size=[{}]]",
                    __FUNCTION__, __LINE__, destination_replica.logical_path(), data_size_str));
                destination_replica.size(0);
            }
        }

        if (phy_path_reg_cond_input.contains(DATA_MODIFY_KW)) {
            destination_replica.mtime(phy_path_reg_cond_input.at(DATA_MODIFY_KW).value());
        }

        // If intermediate, do not attempt to verify checksum as the file does not yet exist
        if (phy_path_reg_cond_input.contains(REGISTER_AS_INTERMEDIATE_KW)) {
            destination_replica.replica_status(INTERMEDIATE_REPLICA);
        }
        else if (phy_path_reg_cond_input.contains(REG_CHKSUM_KW) ||
                 phy_path_reg_cond_input.contains(VERIFY_CHKSUM_KW)) {
            char* chksum{};
            if (const int ec = _dataObjChksum(_comm, destination_replica.get(), &chksum); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "[{}]: _dataObjChksum for {} failed, status = {}",
                    __FUNCTION__, destination_replica.logical_path(), ec));
                return ec;
            }
            destination_replica.checksum(chksum);
        }

        // Register the data object
        const int ec = svrRegDataObj(_comm, destination_replica.get());
        if (ec < 0) {
            irods::log(LOG_ERROR, fmt::format(
                 "{}: svrRegDataObj for {} failed, status = {}",
                 __FUNCTION__, destination_replica.logical_path(), ec));
            return ec;
        }

        // static PEP for filePathReg
        {
            ruleExecInfo_t rei;
            initReiWithDataObjInp(&rei, _comm, _inp);
            rei.doi = destination_replica.get();
            rei.status = ec;

            // make resource properties available as rule session variables
            irods::get_resc_properties_as_kvp(rei.doi->rescHier, rei.condInputData);

            rei.status = applyRule("acPostProcForFilePathReg", NULL, &rei, NO_SAVE_REI);

            clearKeyVal(rei.condInputData);
            free(rei.condInputData);
        } // static PEP for filePathReg

        const auto info_j = ir::to_json(destination_replica);
        freeBBuf(*_out);
        *_out = irods::to_bytes_buffer(info_j.dump());

        return ec;
    } // filePathReg

    int dirPathReg(
        rsComm_t *_comm,
        dataObjInp_t *_inp,
        char *filePath,
        const char *_resc_name)
    {
        fileStatInp_t fileStatInp;
        collInp_t collCreateInp;
        fileOpendirInp_t fileOpendirInp;
        fileClosedirInp_t fileClosedirInp;
        int status;
        int dirFd;
        dataObjInp_t subPhyPathRegInp;
        fileReaddirInp_t fileReaddirInp;
        rodsDirent_t *rodsDirent = NULL;
        rodsObjStat_t *rodsObjStatOut = NULL;
        int forceFlag;

        char* resc_hier = getValByKey( &_inp->condInput, RESC_HIER_STR_KW );
        if ( !resc_hier ) {
            log_api::info("dirPathReg - RESC_HIER_STR_KW is NULL");
            return SYS_INVALID_INPUT_PARAM;
        }

        // =-=-=-=-=-=-=-
        // extract the host location from the resource hierarchy
        std::string location;
        irods::error ret = irods::get_loc_for_hier_string( resc_hier, location );
        if ( !ret.ok() ) {
            irods::log( PASSMSG( "dirPathReg - failed in get_loc_for_hier_string", ret ) );
            return SYS_INVALID_INPUT_PARAM;
        }

        status = collStat( _comm, _inp, &rodsObjStatOut );
        if ( status < 0 || NULL == rodsObjStatOut ) { // JMC cppcheck - nullptr
            freeRodsObjStat( rodsObjStatOut );
            rodsObjStatOut = NULL;
            memset( &collCreateInp, 0, sizeof( collCreateInp ) );
            rstrcpy( collCreateInp.collName, _inp->objPath,
                     MAX_NAME_LEN );

            /* no need to resolve sym link */ // JMC - backport 4845
            addKeyVal( &collCreateInp.condInput, TRANSLATED_PATH_KW, "" ); // JMC - backport 4845

            /* stat the source directory to track the         */
            /* original directory meta-data                   */
            memset( &fileStatInp, 0, sizeof( fileStatInp ) );
            rstrcpy( fileStatInp.fileName, filePath, MAX_NAME_LEN );

            // Get resource location
            rodsLong_t resc_id = 0;
            ret = resc_mgr.hier_to_leaf_id(_resc_name,resc_id);
            if(!ret.ok()) {
                return ret.code();
            }
            std::string location;
            irods::error ret = irods::get_resource_property< std::string >( resc_id, irods::RESOURCE_LOCATION, location );
            if ( !ret.ok() ) {
                irods::log PASSMSG( "dirPathReg - failed in get_resource_property", ret );
                return ret.code();
            }

            snprintf( fileStatInp.addr.hostAddr, NAME_LEN, "%s", location.c_str() );

            rstrcpy( fileStatInp.rescHier, resc_hier, MAX_NAME_LEN );
            rstrcpy( fileStatInp.objPath, _inp->objPath, MAX_NAME_LEN );

            /* create the coll just in case it does not exist */
            status = rsCollCreate( _comm, &collCreateInp );
            clearKeyVal( &collCreateInp.condInput ); // JMC - backport 4835
            if ( status < 0 ) {
                return status;
            }
        }
        else if ( rodsObjStatOut->specColl != NULL ) {
            freeRodsObjStat( rodsObjStatOut );
            log_api::error("mountFileDir: {} already mounted", _inp->objPath);
            return SYS_MOUNT_MOUNTED_COLL_ERR;
        }
        freeRodsObjStat( rodsObjStatOut );
        rodsObjStatOut = NULL;

        memset( &fileOpendirInp, 0, sizeof( fileOpendirInp ) );

        rstrcpy( fileOpendirInp.dirName, filePath, MAX_NAME_LEN );
        rstrcpy( fileOpendirInp.addr.hostAddr, location.c_str(), NAME_LEN );
        rstrcpy( fileOpendirInp.objPath,    _inp->objPath, MAX_NAME_LEN );
        rstrcpy( fileOpendirInp.resc_hier_, resc_hier,              MAX_NAME_LEN );

        dirFd = rsFileOpendir( _comm, &fileOpendirInp );
        if ( dirFd < 0 ) {
            log_api::error("dirPathReg: rsFileOpendir for {} error, status = {}", filePath, dirFd);
            return dirFd;
        }

        fileReaddirInp.fileInx = dirFd;

        if ( getValByKey( &_inp->condInput, FORCE_FLAG_KW ) != NULL ) {
            forceFlag = 1;
        }
        else {
            forceFlag = 0;
        }

        while ( ( status = rsFileReaddir( _comm, &fileReaddirInp, &rodsDirent ) ) >= 0 ) {
            if (!rodsDirent || is_empty_string(rodsDirent->d_name, sizeof(rodsDirent->d_name))) {
                std::free(rodsDirent);
                break;
            }

            if ( strcmp( rodsDirent->d_name, "." ) == 0 ||
                    strcmp( rodsDirent->d_name, ".." ) == 0 ) {
                free( rodsDirent ); // JMC - backport 4835
                continue;
            }

            subPhyPathRegInp = *_inp;
            snprintf( subPhyPathRegInp.objPath, MAX_NAME_LEN, "%s/%s",
                      _inp->objPath, rodsDirent->d_name );

            if ( matchPathname( ExcludePatterns, rodsDirent->d_name, filePath ) ) {
                free( rodsDirent );
                continue;
            }

            fileStatInp_t fileStatInp;
            memset( &fileStatInp, 0, sizeof( fileStatInp ) );

            // Issue #3658 - This section removes trailing slashes from the
            // directory path in the server when the path is already in the catalog.
            //
            // TODO:  This is a localized fix that addresses any trailing slashes
            // in inPath. Any future refactoring of the code that deals with paths
            // would most probably take care of this issue, and the code segment
            // below would/should then be removed.

            char tmpStr[MAX_NAME_LEN]{};
            rstrcpy( tmpStr, filePath, MAX_NAME_LEN );
            const size_t len = strnlen(tmpStr, sizeof(tmpStr));

            for (size_t i = len-1; i > 0 && tmpStr[i] == '/'; i--) {
                tmpStr[i] = '\0';
            }

            snprintf( fileStatInp.fileName, MAX_NAME_LEN, "%s/%s", tmpStr, rodsDirent->d_name );

            rstrcpy( fileStatInp.objPath, subPhyPathRegInp.objPath, MAX_NAME_LEN );
            fileStatInp.addr = fileOpendirInp.addr;
            rstrcpy( fileStatInp.rescHier, resc_hier, MAX_NAME_LEN );

            rodsStat_t *myStat = NULL;
            status = rsFileStat( _comm, &fileStatInp, &myStat );

            if ( status != 0 ) {
                log_api::error("dirPathReg: rsFileStat failed for {}, status = {}", fileStatInp.fileName, status);
                free( rodsDirent ); // JMC - backport 4835
                return status;
            }

            if ( ( myStat->st_mode & S_IFREG ) != 0 ) { /* a file */
                if ( forceFlag > 0 ) {
                    /* check if it already exists */
                    if ( isData( _comm, subPhyPathRegInp.objPath, NULL ) >= 0 ) {
                        free( myStat );
                        free( rodsDirent ); // JMC - backport 4835
                        continue;
                    }
                }

                subPhyPathRegInp.dataSize = myStat->st_size;
                std::string reg_func_name;

                BytesBuf* out = nullptr;

                if ( getValByKey( &_inp->condInput, REG_REPL_KW ) != NULL ) {
                    reg_func_name = "filePathRegRepl";
                    status = filePathRegRepl(_comm, &subPhyPathRegInp, fileStatInp.fileName, _resc_name, &out);
                }
                else {
                    reg_func_name = "filePathReg";
                    addKeyVal( &subPhyPathRegInp.condInput, FILE_PATH_KW, fileStatInp.fileName );
                    status = filePathReg(_comm, &subPhyPathRegInp, _resc_name, &out);
                }

                std::free(out);
                out = nullptr;

                if ( status != 0 ) {
                    if ( _comm->rError.len < MAX_ERROR_MESSAGES ) {
                        log_api::error("[{}:{}] - adding error to stack...", __FUNCTION__, __LINE__);
                        char error_msg[ERR_MSG_LEN];
                        snprintf( error_msg, ERR_MSG_LEN, "dirPathReg: %s failed for %s, status = %d",
                                 reg_func_name.c_str(), subPhyPathRegInp.objPath, status );
                        addRErrorMsg( &_comm->rError, status, error_msg );
                    }
                }
            }
            else if ( ( myStat->st_mode & S_IFDIR ) != 0 ) {    /* a directory */
                dirPathReg( _comm, &subPhyPathRegInp, fileStatInp.fileName, _resc_name );
            }

            free( myStat );
            free( rodsDirent ); // JMC - backport 4835
        }

        if ( status == -1 ) {       /* just EOF */
            status = 0;
        }

        fileClosedirInp.fileInx = dirFd;
        rsFileClosedir( _comm, &fileClosedirInp );

        return status;
    } // dirPathReg

    int mountFileDir(
        rsComm_t*     _comm,
        dataObjInp_t* _inp,
        char*         filePath,
        const char *rescVaultPath)
    {
        collInp_t collCreateInp;
        int status;
        fileStatInp_t fileStatInp;
        rodsStat_t *myStat = NULL;
        rodsObjStat_t *rodsObjStatOut = NULL;

        char* resc_hier = getValByKey( &_inp->condInput, RESC_HIER_STR_KW );
        if ( !resc_hier ) {
            log_api::info("mountFileDir - RESC_HIER_STR_KW is NULL");
            return SYS_INVALID_INPUT_PARAM;
        }

        // =-=-=-=-=-=-=-
        // extract the host location from the resource hierarchy
        std::string location;
        irods::error ret = irods::get_loc_for_hier_string( resc_hier, location );
        if ( !ret.ok() ) {
            irods::log( PASSMSG( "mountFileDir - failed in get_loc_for_hier_string", ret ) );
            return ret.code();
        }

        if ( _comm->clientUser.authInfo.authFlag < LOCAL_PRIV_USER_AUTH ) { // JMC - backport 4832
            log_api::info("mountFileDir - insufficient privilege");
            return CAT_INSUFFICIENT_PRIVILEGE_LEVEL;
        }

        status = collStat( _comm, _inp, &rodsObjStatOut );
        if ( status < 0 || NULL == rodsObjStatOut ) {
            freeRodsObjStat( rodsObjStatOut );
            log_api::info("mountFileDir collstat failed.");
            return status; // JMC cppcheck - nullptr
        }

        if ( rodsObjStatOut->specColl != NULL ) {
            freeRodsObjStat( rodsObjStatOut );
            log_api::error("mountFileDir: {} already mounted", _inp->objPath);
            return SYS_MOUNT_MOUNTED_COLL_ERR;
        }
        freeRodsObjStat( rodsObjStatOut );
        rodsObjStatOut = NULL;

        if ( isCollEmpty( _comm, _inp->objPath ) == False ) {
            log_api::error("mountFileDir: collection {} not empty", _inp->objPath);
            return SYS_COLLECTION_NOT_EMPTY;
        }

        memset( &fileStatInp, 0, sizeof( fileStatInp ) );

        rstrcpy( fileStatInp.fileName, filePath, MAX_NAME_LEN );
        rstrcpy( fileStatInp.objPath, _inp->objPath, MAX_NAME_LEN );
        rstrcpy( fileStatInp.addr.hostAddr,  location.c_str(), NAME_LEN );
        rstrcpy( fileStatInp.rescHier, resc_hier, MAX_NAME_LEN );


        status = rsFileStat( _comm, &fileStatInp, &myStat );

        if ( status < 0 ) {
            fileMkdirInp_t fileMkdirInp;

            log_api::info(
                "mountFileDir: rsFileStat failed for {}, status = {}, create it", fileStatInp.fileName, status);
            memset( &fileMkdirInp, 0, sizeof( fileMkdirInp ) );
            rstrcpy( fileMkdirInp.dirName, filePath, MAX_NAME_LEN );
            rstrcpy( fileMkdirInp.rescHier, resc_hier, MAX_NAME_LEN );
            fileMkdirInp.mode = getDefDirMode();
            rstrcpy( fileMkdirInp.addr.hostAddr,  location.c_str(), NAME_LEN );
            status = rsFileMkdir( _comm, &fileMkdirInp );
            if ( status < 0 ) {
                return status;
            }
        }
        else if ( ( myStat->st_mode & S_IFDIR ) == 0 ) {
            log_api::error("mountFileDir: phyPath {} is not a directory", fileStatInp.fileName);
            free( myStat );
            return USER_FILE_DOES_NOT_EXIST;
        }

        free( myStat );
        /* mk the collection */

        memset( &collCreateInp, 0, sizeof( collCreateInp ) );
        rstrcpy( collCreateInp.collName, _inp->objPath, MAX_NAME_LEN );
        addKeyVal( &collCreateInp.condInput, COLLECTION_TYPE_KW, MOUNT_POINT_STR );

        addKeyVal( &collCreateInp.condInput, COLLECTION_INFO1_KW, filePath );
        addKeyVal( &collCreateInp.condInput, COLLECTION_INFO2_KW, resc_hier );

        /* try to mod the coll first */
        status = rsModColl( _comm, &collCreateInp );

        if ( status < 0 ) {    /* try to create it */
            log_api::info("mountFileDir rsModColl < 0.");
            status = rsRegColl( _comm, &collCreateInp );
        }

        if ( status >= 0 ) {
            log_api::info("mountFileDir rsModColl > 0.");

            char outLogPath[MAX_NAME_LEN];
            /* see if the phyPath is mapped into a real collection */
            if ( getLogPathFromPhyPath( filePath, rescVaultPath, outLogPath ) >= 0 &&
                    strcmp( outLogPath, _inp->objPath ) != 0 ) {
                /* log path not the same as input objPath */
                if ( isColl( _comm, outLogPath, NULL ) >= 0 ) {
                    /* it is a real collection. better set the collection
                     * to read-only mode because any modification to files
                     * through this mounted collection can be trouble */
                    modAccessControlInp_t modAccessControl{};
                    modAccessControl.accessLevel = "read";
                    modAccessControl.userName = _comm->clientUser.userName;
                    modAccessControl.zone = _comm->clientUser.rodsZone;
                    modAccessControl.path = _inp->objPath;
                    if (const auto mod_acl_ec = rsModAccessControl(_comm, &modAccessControl); mod_acl_ec < 0) {
                        log_api::info(
                            "mountFileDir: rsModAccessControl err for {}, stat = {}", _inp->objPath, mod_acl_ec);
                    }
                }
            }
        }

        log_api::info("mountFileDir return status.");
        return status;
    } // mountFileDir

    int unmountFileDir(RsComm* _comm, DataObjInp* _inp)
    {
        rodsObjStat* stat = NULL;

        if (const int ec = collStat(_comm, _inp, &stat); ec < 0 || !stat) {
            std::free(stat);
            return ec;
        }

        if (!stat->specColl) {
            freeRodsObjStat(stat);
            stat = nullptr;

            irods::log(LOG_ERROR, fmt::format(
                "[{}:{}] - [{}] not mounted",
                __FUNCTION__, __LINE__, _inp->objPath));

            return SYS_COLL_NOT_MOUNTED_ERR;
        }

        if (getStructFileType(stat->specColl) >= 0) {
            if (const int ec = _rsSyncMountedColl(_comm, stat->specColl, PURGE_STRUCT_FILE_CACHE); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "[{}:{}] - failed in _rsSyncMountedColl [path=[{}], ec=[{}]]",
                    __FUNCTION__, __LINE__, _inp->objPath, ec));
            }
        }

        freeRodsObjStat(stat);
        stat = nullptr;

        CollInp mod_coll_inp{};
        rstrcpy(mod_coll_inp.collName, _inp->objPath, MAX_NAME_LEN);

        auto cond_input = irods::experimental::make_key_value_proxy(mod_coll_inp.condInput);
        cond_input[COLLECTION_TYPE_KW] = "NULL_SPECIAL_VALUE";
        cond_input[COLLECTION_INFO1_KW] = "NULL_SPECIAL_VALUE";
        cond_input[COLLECTION_INFO2_KW] = "NULL_SPECIAL_VALUE";

        const auto ec = rsModColl(_comm, &mod_coll_inp);
        cond_input.clear(); // Clear the conditional input to avoid a memory leak.

        return ec;
    } // unmountFileDir

    int structFileReg(
        rsComm_t*     _comm,
        dataObjInp_t* _inp)
    {
        // =-=-=-=-=-=-=-
        //
        dataObjInp_t     dataObjInp;
        collInp_t        collCreateInp;
        int              status         = 0;
        char*            collType       = NULL;
        char*            structFilePath = NULL;
        DataObjInfo*     dataObjInfo    = NULL;
        rodsObjStat_t*   rodsObjStatOut = NULL;
        specCollCache_t* specCollCache  = NULL;

        if ( ( structFilePath = getValByKey( &_inp->condInput, FILE_PATH_KW ) )
                == NULL ) {
            log_api::error("structFileReg: No structFilePath input for {}", _inp->objPath);
            return SYS_INVALID_FILE_PATH;
        }

        collType = getValByKey( &_inp->condInput, COLLECTION_TYPE_KW );
        if ( collType == NULL ) {
            log_api::error("structFileReg: Bad COLLECTION_TYPE_KW for structFilePath {}", dataObjInp.objPath);
            return SYS_INTERNAL_NULL_INPUT_ERR;
        }

        const auto len = strnlen(_inp->objPath, sizeof(_inp->objPath));
        if ( strncmp( structFilePath, _inp->objPath, len ) == 0 &&
                ( structFilePath[len] == '\0' || structFilePath[len] == '/' ) ) {
            log_api::error("structFileReg: structFilePath {} inside collection {}", structFilePath, _inp->objPath);
            return SYS_STRUCT_FILE_INMOUNTED_COLL;
        }

        /* see if the struct file is in spec coll */

        if ( getSpecCollCache( _comm, structFilePath, 0,  &specCollCache ) >= 0 ) {
            log_api::error("structFileReg: structFilePath {} is in a mounted path", structFilePath);
            return SYS_STRUCT_FILE_INMOUNTED_COLL;
        }

        status = collStat( _comm, _inp, &rodsObjStatOut );
        if ( status < 0 || NULL == rodsObjStatOut ) {
            free( rodsObjStatOut );
            return status;    // JMC cppcheck - nullptr
        }

        if ( rodsObjStatOut->specColl != NULL ) {
            freeRodsObjStat( rodsObjStatOut );
            log_api::error("structFileReg: {} already mounted", _inp->objPath);
            return SYS_MOUNT_MOUNTED_COLL_ERR;
        }

        freeRodsObjStat( rodsObjStatOut );
        rodsObjStatOut = NULL;

        if ( isCollEmpty( _comm, _inp->objPath ) == False ) {
            log_api::error("structFileReg: collection {} not empty", _inp->objPath);
            return SYS_COLLECTION_NOT_EMPTY;
        }

        memset( &dataObjInp, 0, sizeof( dataObjInp ) );
        rstrcpy( dataObjInp.objPath, structFilePath, sizeof( dataObjInp.objPath ) );
        /* user need to have write permission */
        dataObjInp.openFlags = O_WRONLY;
        status = getDataObjInfoIncSpecColl( _comm, &dataObjInp, &dataObjInfo );
        if ( status < 0 || NULL == dataObjInfo ) { // JMC cppcheck - nullptr
            int myStatus;
            /* try to make one */
            dataObjInp.condInput = _inp->condInput;
            /* have to remove FILE_PATH_KW because getFullPathName will use it */
            rmKeyVal( &dataObjInp.condInput, FILE_PATH_KW );
            myStatus = rsDataObjCreate( _comm, &dataObjInp );
            if ( myStatus < 0 ) {
                log_api::error(
                    "structFileReg: Problem with open/create structFilePath {}, status = {}",
                    dataObjInp.objPath,
                    status);
                return status;
            }
            else {
                openedDataObjInp_t dataObjCloseInp{};
                dataObjCloseInp.l1descInx = myStatus;
                rsDataObjClose( _comm, &dataObjCloseInp );
            }
        }

        char* tmp_hier = getValByKey( &_inp->condInput, RESC_HIER_STR_KW );
        if ( !tmp_hier ) {
            log_api::error("structFileReg - RESC_HIER_STR_KW is NULL");
            return SYS_INVALID_INPUT_PARAM;
        }
        irods::hierarchy_parser parser;
        parser.set_string( std::string( tmp_hier ) );
        std::string resc_name;
        parser.last_resc( resc_name );

        /* mk the collection */

        memset( &collCreateInp, 0, sizeof( collCreateInp ) );
        rstrcpy( collCreateInp.collName, _inp->objPath, MAX_NAME_LEN );
        addKeyVal( &collCreateInp.condInput, COLLECTION_TYPE_KW, collType );
        /* have to use dataObjInp.objPath because structFile path was removed */
        addKeyVal( &collCreateInp.condInput, COLLECTION_INFO1_KW, dataObjInp.objPath );

        /* try to mod the coll first */
        status = rsModColl( _comm, &collCreateInp );

        if ( status < 0 ) { /* try to create it */
            status = rsRegColl( _comm, &collCreateInp );
        }

        return status;
    } // structFileReg

    int structFileSupport(
        rsComm_t *_comm,
        char *collection,
        char *collType,
        char* resc_hier)
    {
        int status;
        subFile_t subFile;
        specColl_t specColl;

        if ( _comm == NULL || collection == NULL || collType == NULL ||
                resc_hier == NULL ) {
            return 0;
        }

        memset( &subFile, 0, sizeof( subFile ) );
        memset( &specColl, 0, sizeof( specColl ) );
        /* put in some fake path */
        subFile.specColl = &specColl;
        rstrcpy( specColl.collection, collection, MAX_NAME_LEN );
        specColl.collClass = STRUCT_FILE_COLL;
        if ( strcmp( collType, HAAW_STRUCT_FILE_STR ) == 0 ) {
            specColl.type = HAAW_STRUCT_FILE_T;
        }
        else if ( strcmp( collType, TAR_STRUCT_FILE_STR ) == 0 ) {
            specColl.type = TAR_STRUCT_FILE_T;
        }
        else if ( strcmp( collType, MSSO_STRUCT_FILE_STR ) == 0 ) {
            specColl.type = MSSO_STRUCT_FILE_T;
        }
        else {
            return 0;
        }

        // =-=-=-=-=-=-=-
        // extract the host location from the resource hierarchy
        std::string location;
        irods::error ret = irods::get_loc_for_hier_string( resc_hier, location );
        if ( !ret.ok() ) {
            irods::log( PASSMSG( "structFileSupport - failed in get_loc_for_hier_string", ret ) );
            return ret.code();
        }

        irods::hierarchy_parser parser;
        parser.set_string( resc_hier );
        std::string first_resc;
        parser.first_resc( first_resc );

        snprintf( specColl.objPath, MAX_NAME_LEN, "%s/myFakeFile", collection );
        rstrcpy( specColl.resource, first_resc.c_str(), NAME_LEN );
        rstrcpy( specColl.rescHier, resc_hier, MAX_NAME_LEN );
        rstrcpy( specColl.phyPath, "/fakeDir1/fakeDir2/myFakeStructFile", MAX_NAME_LEN );
        rstrcpy( subFile.subFilePath, "/fakeDir1/fakeDir2/myFakeFile", MAX_NAME_LEN );
        rstrcpy( subFile.addr.hostAddr, location.c_str(), NAME_LEN );

        rodsStat_t *myStat = NULL;
        status = rsSubStructFileStat( _comm, &subFile, &myStat );
        free( myStat );
        return status != SYS_NOT_SUPPORTED;
    } // structFileSupport

    int linkCollReg(
        rsComm_t *_comm,
        dataObjInp_t *_inp)
    {
        const auto cond_input = irods::experimental::make_key_value_proxy(_inp->condInput);

        if (!cond_input.contains(FILE_PATH_KW)) {
            log_api::error("linkCollReg: No linkPath input for {}", _inp->objPath);
            return SYS_INVALID_FILE_PATH;
        }

        const auto linkPath = cond_input.at(FILE_PATH_KW).value();

        if (!cond_input.contains(COLLECTION_TYPE_KW) || cond_input.at(COLLECTION_TYPE_KW).value() != LINK_POINT_STR) {
            log_api::error("linkCollReg: Bad COLLECTION_TYPE_KW for linkPath {}", _inp->objPath);
            return SYS_INTERNAL_NULL_INPUT_ERR;
        }

        const auto collType = cond_input.at(COLLECTION_TYPE_KW).value();

        if ( _inp->objPath[0] != '/' || linkPath[0] != '/' ) {
            log_api::error(
                "linkCollReg: linkPath {} or collection {} not absolute path", linkPath.data(), _inp->objPath);
            return SYS_COLL_LINK_PATH_ERR;
        }

        auto len = strnlen(_inp->objPath, sizeof(_inp->objPath));
        if (strncmp(linkPath.data(), _inp->objPath, len) == 0 && linkPath[len] == '/') {
            log_api::error("linkCollReg: linkPath {} inside collection {}", linkPath.data(), _inp->objPath);
            return SYS_COLL_LINK_PATH_ERR;
        }

        len = linkPath.size();
        if (strncmp(_inp->objPath, linkPath.data(), len) == 0 && _inp->objPath[len] == '/') {
            log_api::error("linkCollReg: collection {} inside linkPath {}", linkPath.data(), _inp->objPath);
            return SYS_COLL_LINK_PATH_ERR;
        }

        specCollCache_t *specCollCache = NULL;
        if ( getSpecCollCache( _comm, linkPath.data(), 0,  &specCollCache ) >= 0 &&
                specCollCache->specColl.collClass != LINKED_COLL ) {
            log_api::error("linkCollReg: linkPath {} is in a spec coll path", linkPath.data());
            return SYS_COLL_LINK_PATH_ERR;
        }

        rodsObjStat_t *rodsObjStatOut = NULL;
        int status = collStat( _comm, _inp, &rodsObjStatOut );
        if ( status < 0 ) {
            freeRodsObjStat( rodsObjStatOut );
            rodsObjStatOut = NULL;
            /* does not exist. make one */
            collInp_t collCreateInp{};
            rstrcpy( collCreateInp.collName, _inp->objPath, MAX_NAME_LEN );
            status = rsRegColl( _comm, &collCreateInp );
            if ( status < 0 ) {
                log_api::error("linkCollReg: rsRegColl error for  {}, status = {}", collCreateInp.collName, status);
                return status;
            }
            status = collStat( _comm, _inp, &rodsObjStatOut );
            if ( status < 0 ) {
                freeRodsObjStat( rodsObjStatOut );
                return status;
            }

        }

        if ( rodsObjStatOut && // JMC cppcheck - nullptr
                rodsObjStatOut->specColl != NULL &&
                rodsObjStatOut->specColl->collClass != LINKED_COLL ) {
            freeRodsObjStat( rodsObjStatOut );
            log_api::error("linkCollReg: link collection {} in a spec coll path", _inp->objPath);
            return SYS_COLL_LINK_PATH_ERR;
        }

        freeRodsObjStat( rodsObjStatOut );
        rodsObjStatOut = NULL;

        if ( isCollEmpty( _comm, _inp->objPath ) == False ) {
            log_api::error("linkCollReg: collection {} not empty", _inp->objPath);
            return SYS_COLLECTION_NOT_EMPTY;
        }

        /* mk the collection */

        collInp_t collCreateInp{};
        rstrcpy( collCreateInp.collName, _inp->objPath, MAX_NAME_LEN );
        addKeyVal( &collCreateInp.condInput, COLLECTION_TYPE_KW, collType.data() );

        /* have to use dataObjInp.objPath because structFile path was removed */
        addKeyVal( &collCreateInp.condInput, COLLECTION_INFO1_KW, linkPath.data() );

        /* try to mod the coll first */
        status = rsModColl( _comm, &collCreateInp );

        if ( status < 0 ) { /* try to create it */
            status = rsRegColl( _comm, &collCreateInp );
        }

        clearKeyVal(&collCreateInp.condInput);

        return status;
    } // linkCollReg

    auto register_physical_path(
        RsComm* _comm,
        DataObjInp* _inp,
        const std::string_view _resc,
        rodsServerHost* _host_info,
        BytesBuf** _out) -> int
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_inp->condInput);

        if (!cond_input.contains(FILE_PATH_KW)) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}:{}] - No file path input provided [path=[{}]]",
                __FUNCTION__, __LINE__, _inp->objPath));
            return SYS_INVALID_FILE_PATH;
        }

        if (!cond_input.contains(RESC_HIER_STR_KW)) {
            irods::log(LOG_NOTICE, fmt::format(
                "[{}:{}] - resource hierarchy keyword not provided [path=[{}]]",
                __FUNCTION__, __LINE__, _inp->objPath));
            return SYS_INVALID_INPUT_PARAM;
        }

        const auto resc_hier = cond_input.at(RESC_HIER_STR_KW).value();

        // Copy into a new buffer because the FILE_PATH_KW will be overwritten later
        char file_path[MAX_NAME_LEN]{};
        rstrcpy(file_path, cond_input.at(FILE_PATH_KW).value().data(), MAX_NAME_LEN);

        DataObjInfo info{};
        rstrcpy(info.objPath, _inp->objPath, MAX_NAME_LEN );
        rstrcpy(info.filePath, file_path, MAX_NAME_LEN );
        rstrcpy(info.rescName, _resc.data(), NAME_LEN );
        rstrcpy(info.rescHier, cond_input.at(RESC_HIER_STR_KW).value().data(), MAX_NAME_LEN);
        if (const auto ret = resc_mgr.hier_to_leaf_id(info.rescHier, info.rescId); !ret.ok()) {
            irods::log(PASS(ret));
        }

        // Ensure that the user has permissions to register this path in the catalog.
        if (const auto check_type = getchkPathPerm(_comm, _inp, &info);
            !cond_input.contains(NO_CHK_FILE_PERM_KW) && NO_CHK_PATH_PERM != check_type) {
            std::string location;
            if (const auto ret = irods::get_loc_for_hier_string(resc_hier.data(), location); !ret.ok()) {
                irods::log(PASSMSG(
                    fmt::format("[{}:{}] - failed in get_loc_for_hier_string", __FUNCTION__, __LINE__), ret));
                return ret.code();
            }

            fileOpenInp_t perm_inp{};
            rstrcpy(perm_inp.fileName, file_path, MAX_NAME_LEN);
            rstrcpy(perm_inp.addr.hostAddr, location.c_str(), NAME_LEN);
            if (const int ec = chkFilePathPerm(_comm, &perm_inp, _host_info, check_type); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "[{}:{}] - chkFilePathPerm error [path=[{}], ec=[{}]]",
                    __FUNCTION__, __LINE__, _inp->objPath, ec));
                return ec;
            }
        }

        // Special case for collections(?)
        if (cond_input.contains(COLLECTION_KW)) {
            if (!cond_input.contains(EXCLUDE_FILE_KW)) {
                return dirPathReg(_comm, _inp, file_path, _resc.data());
            }

            ExcludePatterns = readPathnamePatternsFromFile(_comm,
                              cond_input.at(EXCLUDE_FILE_KW).value().data(),
                              resc_hier.data());

            const auto free_exclude_patterns = irods::at_scope_exit{[] {
                freePathnamePatterns(ExcludePatterns);
                ExcludePatterns = nullptr;
            }};

            return dirPathReg(_comm, _inp, file_path, _resc.data());
        }

        // Special case for mounted collections(?)
        if (cond_input.contains(COLLECTION_TYPE_KW) && cond_input.at(COLLECTION_TYPE_KW).value() == MOUNT_POINT_STR) {
            rodsLong_t resc_id = 0;
            if (const auto ret = resc_mgr.hier_to_leaf_id(_resc.data(), resc_id); !ret.ok()) {
                return ret.code();
            }

            std::string resc_vault_path;
            if (const auto ret = irods::get_resource_property<std::string>(resc_id, irods::RESOURCE_PATH, resc_vault_path); !ret.ok()) {
                irods::log(PASSMSG(fmt::format("[{}:{}] - failed in get_resource_property", __FUNCTION__, __LINE__), ret));
                return ret.code();
            }

            return mountFileDir(_comm, _inp, file_path, resc_vault_path.c_str());
        }

        // This flag is set by rsDataObjOpen to allow creation of replicas via the streaming
        // interface (e.g. dstream).
        const bool register_replica = irods::experimental::key_value_proxy{_comm->session_props}.contains(REG_REPL_KW);

        if (register_replica || cond_input.contains(REG_REPL_KW)) {
            return filePathRegRepl(_comm, _inp, file_path, _resc, _out);
        }

        return filePathReg(_comm, _inp, _resc, _out);
    } // register_physical_path

    auto rs_register_physical_path(RsComm* _comm, DataObjInp* _inp, BytesBuf** _out) -> int
    {
        if (!_inp || !_out) {
            return SYS_INVALID_INPUT_PARAM;
        }

        auto cond_input = irods::experimental::make_key_value_proxy(_inp->condInput);

        // TODO: Need to actually handle errors here
        //const auto make_out_point_somewhere = irods::at_scope_exit{[&_out] {
            //if (!*_out) {
                //*_out = irods::to_bytes_buffer("{}");
            //}
        //}};
        *_out = irods::to_bytes_buffer("{}");

        // Only admin users can bypass permissions checks.
        if (cond_input.contains(NO_CHK_FILE_PERM_KW) &&
            _comm->proxyUser.authInfo.authFlag < LOCAL_PRIV_USER_AUTH ) {
            return SYS_NO_API_PRIV;
        }

        namespace fs = irods::experimental::filesystem;

        // Also covers checking of empty paths.
        if (fs::path{_inp->objPath}.object_name().empty()) {
            return USER_INPUT_PATH_ERR;
        }

        // NOTE:: resource_redirect can wipe out the specColl due to a call to getDataObjIncSpecColl
        //        which nullifies the specColl in the case of certain special collections ( LINKED ).
        //        this block of code needs to be called before redirect to handle that case as it doesn't
        //        need the resource hierarchy anyway.  this is the sort of thing i'd like to avoid in
        //        the future
        const std::string_view coll_type = cond_input.contains(COLLECTION_TYPE_KW)
                                         ? cond_input.at(COLLECTION_TYPE_KW).value() : "";

        if (!coll_type.empty()) {
            if (coll_type == UNMOUNT_STR) {
                return unmountFileDir(_comm, _inp);
            }
            else if (coll_type == LINK_POINT_STR) {
                return linkCollReg(_comm, _inp);
            }
        }

        // determine if a hierarchy has been passed by kvp, if so use it.
        // otherwise determine a resource hierarchy given dst hier or default resource
        std::string hier;
        if (!cond_input.contains(RESC_HIER_STR_KW)) {
            // if no hier is provided, determine if a resource was specified
            if (cond_input.contains(DEST_RESC_NAME_KW)) {
                const auto dest_resc = cond_input.at(DEST_RESC_NAME_KW).value();

                // if we do have a dest resc, see if it has a parent or a child
                irods::resource_ptr resc;
                if (const auto ret = resc_mgr.resolve(dest_resc.data(), resc); !ret.ok()) {
                    irods::log(PASS(ret));
                    return ret.code();
                }

                irods::resource_ptr parent_resc;
                const bool has_parent = resc->get_parent(parent_resc).ok();
                const bool has_child = resc->num_children() > 0;

                if (has_parent && has_child) {
                    // Mid-hierarchy resource
                    return HIERARCHY_ERROR;
                }
                else if (has_parent && !has_child) {
                    // Leaf resource
                    if (const auto ret = resc_mgr.get_hier_to_root_for_resc(dest_resc.data(), hier); !ret.ok()) {
                        irods::log(PASS(ret));
                        return ret.code();
                    }

                    cond_input[RESC_HIER_STR_KW] = hier;
                    cond_input[DEST_RESC_NAME_KW] = irods::hierarchy_parser{hier}.first_resc();
                }
                else if (!has_parent && !has_child) {
                    // Standalone resource
                    hier = dest_resc.data();
                    cond_input[RESC_HIER_STR_KW] = hier;
                }
                else {
                    // Root resource - needs to be resolved
                    try {
                        const auto result = irods::resolve_resource_hierarchy(irods::CREATE_OPERATION, _comm, *_inp);
                        hier = std::get<std::string>(result);
                        cond_input[RESC_HIER_STR_KW] = hier;
                    }
                    catch (const irods::exception& e) {
                        irods::log(LOG_ERROR, fmt::format(
                            "[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.client_display_what()));
                        return e.code();
                    }
                }
            }
            else {
                // no resc is specified, request a hierarchy given the default resource
                try {
                    const auto result = irods::resolve_resource_hierarchy(irods::CREATE_OPERATION, _comm, *_inp);
                    hier = std::get<std::string>(result);
                }
                catch (const irods::exception& e) {
                    irods::log(LOG_ERROR, fmt::format(
                        "[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.client_display_what()));
                    return e.code();
                }
                cond_input[RESC_HIER_STR_KW] = hier;
            }
        }
        else {
            hier = cond_input.at(RESC_HIER_STR_KW).value().data();
        }

        // structfile collection registration requires the resource hierarchy
        const auto collection_is_structfile = !coll_type.empty() &&
            (coll_type == HAAW_STRUCT_FILE_STR ||
             coll_type == TAR_STRUCT_FILE_STR ||
             coll_type == MSSO_STRUCT_FILE_STR);
        if (collection_is_structfile) {
            return structFileReg(_comm, _inp);
        }

        rodsLong_t resc_id = 0;
        if (const auto ret = resc_mgr.hier_to_leaf_id(hier, resc_id); !ret.ok()) {
            return ret.code();
        }

        std::string location;
        if (const auto ret = irods::get_resource_property<std::string>(resc_id, irods::RESOURCE_LOCATION, location); !ret.ok()) {
            irods::log(PASSMSG("failed in get_resource_property", ret));
            return ret.code();
        }

        rodsHostAddr_t addr{};
        rstrcpy(addr.hostAddr, location.c_str(), LONG_NAME_LEN);

        rodsServerHost_t* host_info = nullptr;
        const int remoteFlag = resolveHost(&addr, &host_info);
        if (remoteFlag < 0) {
            return remoteFlag;
        }

        // We do not need to redirect if we do not need to stat the file which is to be registered
        if (cond_input.contains(DATA_SIZE_KW) || LOCAL_HOST == remoteFlag) {
            const auto leaf_resc = irods::hierarchy_parser{hier}.last_resc();
            return register_physical_path(_comm, _inp, leaf_resc, host_info, _out);
        }
        else if (REMOTE_HOST ==  remoteFlag) {
            return remotePhyPathReg(_comm, _inp, host_info, _out);
        }

        irods::log(LOG_ERROR, fmt::format(
            "[{}:{}] - resolveHost returned unrecognized value [%d]",
            __FUNCTION__, __LINE__, remoteFlag));

        return SYS_UNRECOGNIZED_REMOTE_FLAG;
    } // rs_register_physical_path

    using operation = std::function<int(RsComm*, DataObjInp*, BytesBuf**)>;
    const operation op = rs_register_physical_path;
    #define CALL_REGISTER_PHYSICAL_PATH call_register_physical_path
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace {
    using operation = std::function<int(RsComm*, DataObjInp*, BytesBuf**)>;
    const operation op{};
    #define CALL_REGISTER_PHYSICAL_PATH nullptr
} // anonymous namespace

#endif // RODS_SERVER

// The plugin factory function must always be defined.
extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> irods::api_entry*
{
#ifdef RODS_SERVER
    irods::client_api_allowlist::add(REGISTER_PHYSICAL_PATH_APN);
#endif // RODS_SERVER

    // clang-format off
    irods::apidef_t def{
        REGISTER_PHYSICAL_PATH_APN,     // API number
        RODS_API_VERSION,               // API version
        REMOTE_USER_AUTH,               // Client auth
        REMOTE_USER_AUTH,               // Proxy auth
        "DataObjInp_PI", 0,             // In PI / bs flag
        "BinBytesBuf_PI", 0,            // Out PI / bs flag
        op,                             // Operation
        "api_register_physical_path",   // Operation name
        clearDataObjInp,                // Clear input function
        clearBytesBuffer,               // Clear output function
        (funcPtr) CALL_REGISTER_PHYSICAL_PATH
    };
    // clang-format on

    auto* api = new irods::api_entry{def};

    api->in_pack_key = "DataObjInp_PI";
    api->in_pack_value = DataObjInp_PI;

    api->out_pack_key = "BinBytesBuf_PI";
    api->out_pack_value = BytesBuf_PI;

    return api;
} // plugin_factory
