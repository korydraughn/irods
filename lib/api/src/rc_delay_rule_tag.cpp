#include "irods/delay_rule_tag.h"

#include "irods/apiNumber.h"
#include "irods/procApiRequest.h"
#include "irods/rodsErrorTable.h"

auto rc_delay_rule_tag(RcComm* _comm, DelayRuleTagInput* _input) -> int
{
    if (!_comm || !_input) {
        return SYS_INVALID_INPUT_PARAM;
    }

    return procApiRequest(_comm, DELAY_RULE_TAG_AN, _input, nullptr, nullptr, nullptr);
} // rc_delay_rule_tag
