#ifndef __FIVEM_STATS_H__
#define __FIVEM_STATS_H__

enum fivem_stat {
    STAT_PASS_TCP                        = 0,
    STAT_PASS_UDP_WHITELISTED            = 1,
    STAT_DROP_UDP_NOT_WHITELISTED        = 2,
    STAT_DROP_UDP_EXPIRED                = 3,
    STAT_DROP_MALFORMED                  = 4,
    STAT_TCP_ESTABLISHED_INSERTS         = 5,
    STAT_TCP_L7_PROMOTED                 = 6,
    STAT_TCP_L7_MATCH_NO_EST             = 7,
    STAT_DROP_UDP_RATELIMIT              = 8,
    STAT_DROP_TCP_INITCONNECT_RATELIMIT  = 9,
    STAT_DROP_UDP_ENET_MALFORMED         = 10,
    STAT_DROP_UDP_UNHEALTHY              = 11,
    STAT_TCP_POST_CLIENT_SEEN            = 12,
    STAT_TCP_GETINFO_SEEN                = 13,
    STAT_DROP_TCP_GETINFO_RATELIMIT      = 14,
    STAT_DROP_TCP_BAD_USER_AGENT         = 15,
    STAT_DROP_TCP_NO_SYN                 = 16,
    STAT_DROP_TCP_GLOBAL_RATELIMIT        = 17,
    STAT_DROP_TCP_TOO_MANY_OPEN          = 18,
    STAT_MAX                             = 19,
};

#endif
