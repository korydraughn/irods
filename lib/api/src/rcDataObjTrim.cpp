#include "irods/dataObjTrim.h"
#include "irods/procApiRequest.h"
#include "irods/apiNumber.h"

#include <cstring>

/**
 * \fn rcDataObjTrim (rcComm_t *conn, dataObjInp_t *dataObjInp)
 *
 * \brief Trim down the number of replica of a data object by deleting some
 *       replicas.
 *
 * \user client
 *
 * \ingroup data_object
 *
 * \since 1.0
 *
 *
 * \remark none
 *
 * \note none
 *
 * \usage
 * Trim the data object /myZone/home/john/myfile by deleting replica in myResource.
 * Also keep a minimum of 1 copy of the data after the trim :
 * \n dataObjInp_t dataObjInp;
 * \n memset(&dataObjInp, 0, sizeof(dataObjInp));
 * \n rstrcpy (dataObjInp.objPath, "/myZone/home/john/myfile", MAX_NAME_LEN);
 * \n addKeyVal (&dataObjInp->condInput, COPIES_KW, "1");
 * \n addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, "myResource");
 * \n status = rcDataObjTrim (conn, &dataObjInp);
 * \n if (status < 0) {
 * \n .... handle the error
 * \n }
 *
 * \param[in] conn - A rcComm_t connection handle to the server.
 * \param[in] dataObjInp - Elements of dataObjInp_t used :
 *    \li char \b objPath[MAX_NAME_LEN] - full path of the data object.
 *    \li keyValPair_t \b condInput - keyword/value pair input. Valid keywords:
 *    \n COPIES_KW - the minimum number of current replicas to keep. The
 *         replicas will be deleted according to input instruction but
 *         the remaining won't go below this value. If not specified,
 *         the default value is 2.
 *    \n ADMIN_KW - admin user trims other user's files.
 *            This keyWd has no value.
 *    \n REPL_NUM_KW - The replica number of the replica to delete.
 *    \n RESC_NAME_KW - delete replica stored in this resource.
 *    \n DRYRUN_KW - Do a dry run. No replica will actually be trimmed.
 *            This keyWd has no value.
 *
 * \return integer
 * \retval 0 on success
 * \sideeffect none
 * \pre none
 * \post none
 * \sa none
 **/

int
rcDataObjTrim( rcComm_t *conn, dataObjInp_t *dataObjInp ) {
    int status;

    status = procApiRequest( conn, DATA_OBJ_TRIM_AN,  dataObjInp, NULL,
                             ( void ** ) NULL, NULL );

    return status;
}

