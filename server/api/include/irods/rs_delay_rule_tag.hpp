#ifndef IRODS_RS_DELAY_RULE_TAG_HPP
#define IRODS_RS_DELAY_RULE_TAG_HPP

/// \file

#include "irods/delay_rule_tag.h"

struct RsComm;

/// TODO
///
/// \since 5.0.0
int rs_delay_rule_tag(RsComm* _comm, DelayRuleTagInput* _input);

#endif // IRODS_RS_DELAY_RULE_TAG_HPP
