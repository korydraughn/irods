#ifndef IRODS_SWITCH_USER_TYPES_H
#define IRODS_SWITCH_USER_TYPES_H

typedef struct SwitchUserInput // NOLINT(modernize-use-using)
{
    // NOLINTBEGIN(modernize-avoid-c-arrays)
    char username[64];
    char zone[64];
    // NOLINTEND(modernize-avoid-c-arrays)
    int update_proxy_user;
    int close_svr_to_svr_connections;
} switchUserInp_t;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SwitchUserInp_PI "str username[64]; str zone[64]; int update_proxy_user; int close_svr_to_svr_connections;"

#endif // IRODS_SWITCH_USER_TYPES_H
