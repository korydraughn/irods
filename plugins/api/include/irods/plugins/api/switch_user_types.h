#ifndef IRODS_SWITCH_USER_TYPES_H
#define IRODS_SWITCH_USER_TYPES_H

typedef struct SwitchUserInput // NOLINT(modernize-use-using)
{
    // NOLINTBEGIN(modernize-avoid-c-arrays)
    char username[64];
    char zone[64];
    // NOLINTEND(modernize-avoid-c-arrays)
} switchUserInp_t;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SwitchUserInp_PI "str username[64]; str zone[64];"

typedef struct SwitchUserOutput // NOLINT(modernize-use-using)
{
    // NOLINTBEGIN(modernize-avoid-c-arrays)
    char user_type[64];
    int privilege_level;
    // NOLINTEND(modernize-avoid-c-arrays)
} switchUserOut_t;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SwitchUserOut_PI "str user_type[64]; int privilege_level;"

#endif // IRODS_SWITCH_USER_TYPES_H

