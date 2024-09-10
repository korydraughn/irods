#include "irods/delay_rule_tag_clear.h"

#include "irods/apiNumber.h"
#include "irods/procApiRequest.h"
#include "irods/rodsErrorTable.h"

auto rc_delay_rule_tag_clear(RcComm* _comm, DelayRuleTagClearInput* _input) -> int
{
    if (!_comm || !_input) {
        return SYS_INVALID_INPUT_PARAM;
    }

    return procApiRequest(_comm, DELAY_RULE_TAG_CLEAR_AN, _input, nullptr, nullptr, nullptr);
} // rc_delay_rule_tag_clear
