#ifndef EXEC_RULE_EXPRESSION_H
#define EXEC_RULE_EXPRESSION_H

#include "rodsDef.h"
#include "rodsType.h"
#include "msParam.h"

struct RcComm;

typedef struct ExecRuleExpression {
    bytesBuf_t      rule_text_;
    bytesBuf_t      packed_rei_;
    msParamArray_t* params_;
} exec_rule_expression_t;

#define ExecRuleExpression_PI "struct BytesBuf_PI; struct BytesBuf_PI; struct *MsParamArray_PI;"

int rcExecRuleExpression(struct RcComm*,exec_rule_expression_t*);

#endif
