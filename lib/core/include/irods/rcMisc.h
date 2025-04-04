#ifndef IRODS_RC_MISC_H
#define IRODS_RC_MISC_H

#include "irods/rods.h"
#include "irods/rodsError.h"
#include "irods/objInfo.h"
#include "irods/rodsPath.h"
#include "irods/bulkDataObjPut.h"

#include <netinet/in.h>

#ifdef __cplusplus
#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <optional>

extern "C" {
#endif // __cplusplus

void clearModAccessControlInp(void*);

void clearModAVUMetadataInp(void*);

void clearDataObjCopyInp(void*);

void clearUnregDataObj(void*);

void clearModDataObjMetaInp(void*);

void clearRegReplicaInp(void* voidInp);

void clearGeneralAdminInput(void* _p);

void clearOpenedDataObjInp(void* _p);

void clearSpecificQueryInp(void* _p);

void clearTicketAdminInp(void* _p);

void clearExecMyRuleInp(void* _p);

void clearRuleExecModifyInput(void* _p);

void clearExecCmd(void* _p);

void clearExecRuleExpressionInput(void* _p);

void clearRuleExecSubmitInput(void* _p);

void clearAuthRequestOut(void* _p);

void clearAuthCheckOut(void* _p);

void clearPamAuthRequestOut(void* _p);

void clearRodsObjStat(void* _p);

void clearExecCmdOut(void* _p);

void clearDataObjInfo(void* _p);

void clearBytesBuffer(void* _p);

void clearSwitchUserInput(void* _p);

void clearRescQuota(void* _p);

void clearRescQuotaInp(void* _p);

void clearGenquery2Input(void* _p);

void clearDelayRuleLockInput(void* _p);

void clearDelayRuleUnlockInput(void* _p);

void clearMiscSvrInfo(void* _p);

int isPath(char* path);

rodsLong_t getFileSize(char* path);

int freeBBuf(bytesBuf_t* myBBuf);

int clearBBuf(bytesBuf_t* myBBuf);

int freeRError(rError_t* myError);

int replErrorStack(rError_t* srcRError, rError_t* destRError);

int freeRErrorContent(rError_t* myError);

int parseUserName(const char* fullUserNameIn, char* userName, char* userZone);

int myHtonll(rodsLong_t inlonglong, rodsLong_t* outlonglong);

int myNtohll(rodsLong_t inlonglong, rodsLong_t* outlonglong);

int statToRodsStat(rodsStat_t* rodsStat, struct stat* myFileStat);

int rodsStatToStat(struct stat* myFileStat, rodsStat_t* rodsStat);

int direntToRodsDirent(rodsDirent_t* rodsDirent, struct dirent* fileDirent);

int getLine(FILE* fp, char* buf, int bufsz);

int getStrInBuf(char** inbuf, char* outbuf, int* inbufLen, int outbufLen);

int getNextEleInStr(char** inbuf, char* outbuf, int* inbufLen, int maxOutLen);

int getZoneNameFromHint(const char* rcatZoneHint, char* zoneName, int len);

int freeDataObjInfo(dataObjInfo_t* dataObjInfo);

int freeAllDataObjInfo(dataObjInfo_t* dataObjInfoHead);

char* getValByKey(const keyValPair_t* condInput, const char* keyWord);

int getIvalByInx(inxIvalPair_t* inxIvalPair, int inx, int* outValue);

char* getValByInx(inxValPair_t* inxValPair, int inx);

int replKeyVal(const keyValPair_t* srcCondInput, keyValPair_t* destCondInput);

int copyKeyVal(const keyValPair_t* srcCondInput, keyValPair_t* destCondInput);

int replDataObjInp(dataObjInp_t* srcDataObjInp, dataObjInp_t* destDataObjInp);

int replDataObjInfo(struct DataObjInfo* _dst, struct DataObjInfo* _src);

int replSpecColl(specColl_t* inSpecColl, specColl_t** outSpecColl);

int addKeyVal(keyValPair_t* condInput, const char* keyWord, const char* value);

int addInxIval(inxIvalPair_t* inxIvalPair, int inx, int value);

int addInxVal(inxValPair_t* inxValPair, int inx, const char* value);

int addStrArray(strArray_t* strArray, char* value);

int resizeStrArray(strArray_t* strArray, int newSize);

int queueDataObjInfo(dataObjInfo_t** dataObjInfoHead, dataObjInfo_t* dataObjInfo, int singleInfoFlag, int topFlag);

int dequeDataObjInfo(dataObjInfo_t** dataObjInfoHead, dataObjInfo_t* dataObjInfo); // JMC - backport 4590

int clearKeyVal(keyValPair_t* condInput);

int clearInxIval(inxIvalPair_t* inxIvalPair);

int clearInxVal(inxValPair_t* inxValPair);

int moveKeyVal(keyValPair_t* destKeyVal, keyValPair_t* srcKeyVal);

int rmKeyVal(keyValPair_t* condInput, const char* keyWord);

int sendTranHeader(int sock,
                   int oprType,
                   int flags,
                   rodsLong_t offset,
                   rodsLong_t length);

int freeGenQueryOut(genQueryOut_t** genQueryOut);

int freeGenQueryInp(genQueryInp_t** genQueryInp);

void clearGenQueryInp(void* voidInp);

sqlResult_t* getSqlResultByInx(genQueryOut_t* genQueryOut, int attriInx);

void clearGenQueryOut(void* );

int catGenQueryOut(genQueryOut_t* targGenQueryOut,
                   genQueryOut_t* genQueryOut,
                   int maxRowCnt);

void clearBulkOprInp(void* );

int getUnixUid(char* userName);

int getUnixUsername(int uid, char* username, int username_len);

int getUnixGroupname(int gid, char* groupname, int groupname_len);

int parseMultiStr(char* strInput, strArray_t* strArray);

void getNowStr(char* timeStr);

int getLocalTimeFromRodsTime(const char* timeStrIn, char* timeStrOut);

int getLocalTimeStr(struct tm* mytm, char* timeStr);

int getOffsetTimeStr(char* timeStr, const char* offSet);

void updateOffsetTimeStr(char* timeStr, int offset);

int checkDateFormat(char* s);

int localToUnixTime(char* localTime, char* unixTime);

int printErrorStack(rError_t* rError);

int getDataObjInfoCnt(dataObjInfo_t* dataObjInfoHead);

int appendRandomToPath(char* trashPath);

int isBundlePath(char* myPath); // JMC - backport 4552

int isTrashPath(char* myPath);

orphanPathType_t isOrphanPath(char* myPath);

int isHomeColl(char* myPath);

int isTrashHome(char* myPath);

int openRestartFile(char* restartFile, rodsRestart_t* rodsRestart);

int setStateForResume(rcComm_t* conn,
                      rodsRestart_t* rodsRestart,
                      char* restartPath,
                      objType_t objType,
                      keyValPair_t* condInput,
                      int deleteFlag);

int writeRestartFile(rodsRestart_t* rodsRestart, char* lastDonePath);

int procAndWriteRestartFile(rodsRestart_t* rodsRestart, char* donePath);

int setStateForRestart(rodsRestart_t* rodsRestart, rodsPath_t* targPath, rodsArguments_t* rodsArgs);

int chkStateForResume(rcComm_t* conn,
                      rodsRestart_t* rodsRestart,
                      char* targPath,
                      rodsArguments_t* rodsArgs,
                      objType_t objType,
                      keyValPair_t* condInput,
                      int deleteFlag);

int addTagStruct(tagStruct_t* condInput, char* preTag, char* postTag, char* keyWord);

void clearFileOpenInp(void* voidInp);

void clearDataObjInp(void*);

void clearCollInp(void*);

void clearAuthResponseInp(void* myInStruct);

int isInteger(const char* inStr);

int addIntArray(intArray_t* intArray, int value);

int getMountedSubPhyPath(char* logMountPoint, char* phyMountPoint, char* logSubPath, char* phySubPathOut);

int resolveSpecCollType(char* type, char* collection, char* collInfo1, char* collInfo2, specColl_t* specColl);

int getSpecCollTypeStr(specColl_t* specColl, char* outStr);

int getErrno(int errCode);

int getIrodsErrno(int irodError);

structFileOprType_t getSpecCollOpr(keyValPair_t* condInput, specColl_t* specColl);

void resolveStatForStructFileOpr(keyValPair_t* condInput, rodsObjStat_t* rodsObjStatOut);

int keyValToString(keyValPair_t* list, char** string);

int keyValFromString(char* string, keyValPair_t** list);

int convertDateFormat(char* s, char* currTime);

int getNextRepeatTime(char* currTime, char* delayStr, char* nextTime);

int printError(rcComm_t* Conn, int status, char* routineName);

/// Parse a GenQuery1 string and store the result into a genQueryInp_t structure.
///
/// \param[in]       _s The GenQuery1 string to parse.
/// \param[in,out] _out A pointer to a genQueryInp_t to fill.
///
/// \return An integer.
/// \retval  0 On success.
/// \retval <0 On failure.
///
/// \since 5.0.0
int parse_genquery1_string(const char* _s, genQueryInp_t* _out);

int printGenQueryOut(FILE* fd, char* format, char* hint, genQueryOut_t* genQueryOut);

int appendToByteBuf(bytesBuf_t* bytesBuf, char* str);

char* getAttrNameFromAttrId(int cid);

int getAttrIdFromAttrName(char* cname);

int showAttrNames();

int getSelVal(char* c);

int parseCachedStructFileStr(char* collInfo2, specColl_t* specColl);

int makeCachedStructFileStr(char* collInfo2, specColl_t* specColl);

int getLineInBuf(char** inbuf, char* outbuf, int bufLen);

int freeRodsObjStat(rodsObjStat_t* rodsObjStat);

int parseHostAddrStr(char* hostAddr, rodsHostAddr_t* addr);

void printReleaseInfo(char* cmdName);

unsigned int seedRandom();

int initBulkDataObjRegInp(genQueryOut_t* bulkDataObjRegInp);

int initBulkDataObjRegOut(genQueryOut_t** bulkDataObjRegOut);

int untarBuf(char* phyBunDir, bytesBuf_t* tarBBuf);

int tarToBuf(char* phyBunDir, bytesBuf_t* tarBBuf);

int readToByteBuf(int fd, bytesBuf_t* bytesBuf);

int writeFromByteBuf(int fd, bytesBuf_t* bytesBuf);

int initAttriArrayOfBulkOprInp(bulkOprInp_t* bulkOprInp);

int fillAttriArrayOfBulkOprInp(char* objPath,
                               int dataMode,
                               char* inpChksum,
                               int offset,
                               bulkOprInp_t* bulkOprInp);

int getPhyBunPath(const char* collection,
                  const char* objPath,
                  const char* phyBunDir,
                  char* outPhyBunPath);

int unbunBulkBuf(char* phyBunDir, bulkOprInp_t* bulkOprInp, bytesBuf_t* bulkBBuf);

int mySetenvStr(const char* envname, const char* envval);

int mySetenvInt(char* envname, int envval);

int getNumFilesInDir(const char* mydir);

int getRandomArray(int** randomArray, int size);

// Issue 3988: replaces isPathSymlink() function below which is soon to be deprecated.
// Returns:
//         0 - treat the parameter path as NOT a symlink
//         1 - treat the parameter path as a symlink
//        <0 - Error code (message in the message stack)
int isPathSymlink_err(rodsArguments_t* rodsArgs, const char* path);

// Issue 3988: will be DEPRECATED in a future release in favor of the
// function above (isPathSymlink_err). The isPathSymlink() function does not return error
// codes, although it will print error messages as needed.
// Returns:
//         0 - treat the parameter path as NOT a symlink
//         1 - treat the parameter path as a symlink
int isPathSymlink(rodsArguments_t* rodsArgs, const char* path); // DEPRECATED in a future release

int getAttriInAttriArray(const char* objPath,
                         genQueryOut_t* attriArray,
                         int* outDataMode,
                         char** outChksum);

// clang-format off
__attribute__((deprecated))
char* trimSpaces(char* str);
// clang-format on

// clang-format off
__attribute__((deprecated))
char* trimPrefix(char* str);
// clang-format on

int convertListToMultiString(char* strInput, int input);

int startsWith(const char* str, const char* prefix);

int splitMultiStr(char* strInput, strArray_t* strArray);

int hasSymlinkInDir(const char* mydir);

int hasSymlinkInPath(const char* myPath);

int hasSymlinkInPartialPath(const char* myPath, int pos);

int myWrite(int sock, void* buf, int len, int* bytesWritten);

int myRead(int sock, void* buf, int len, int* bytesRead, struct timeval* tv);

int getPathStMode(const char* p);

int getaddrinfo_with_retry(const char* _node,
                           const char* _service,
                           const struct addrinfo* _hints,
                           struct addrinfo** _res);

int get_canonical_name(const char* _hostname, char* _buf, size_t _len);

int load_in_addr_from_hostname(const char* _hostname, struct in_addr* _out);

/// Sets the display name for a single connection in the output of "ips".
///
/// This function should be called before making any connections to the server.
///
/// \param[in] _display_name The name that identifies the connection. This is normally
///                          the name of the client application.
///
/// \since 4.3.0
void set_ips_display_name(const char* _display_name);

/// Determines whether the given buffer could contain sensitive data.
///
/// The contents of the buffer is considered sensitive if it contains any of the following
/// byte sequences:
/// - <authPlugReqInp_PI>
///
/// \param[in] _buffer      The buffer.
/// \param[in] _buffer_size The size of the buffer.
///
/// \return An integer value.
/// \retval 1 If true.
/// \retval 0 Otherwise.
///
/// \since 4.2.12
int may_contain_sensitive_data(const char* _buffer, size_t _buffer_size);

#ifdef __cplusplus
} // extern "C"

/// Defines the set of matching schemes used during hostname resolution against
/// the host_resolution information defined in the server_config.json file.
///
/// \since 4.2.9
enum class hostname_resolution_scheme
{
    match_preferred,    ///< Use the first entry's address.
    match_longest       ///< Use the entry with the longest address.
}; // enum class hostname_resolution_scheme

/// Returns a hostname from the host_resolution information based on a matching scheme.
///
/// \param[in] _hostname The hostname to resolve. If the provided hostname does not
///                      exist in the JSON object, std::nullopt is returned.
/// \param[in] _scheme   The matching scheme that controls how a hostname is resolved.
///
/// \return A std::optional<std::string> representing the hostname.
/// \retval std::string  If \p _hosts_config contains a match.
/// \retval std::nullopt Otherwise.
///
/// \since 4.2.9
auto resolve_hostname(const std::string_view _hostname, hostname_resolution_scheme _scheme)
    -> std::optional<std::string>;

#endif // __cplusplus

#endif // IRODS_RC_MISC_H

