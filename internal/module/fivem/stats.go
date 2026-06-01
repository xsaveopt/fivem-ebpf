package fivem

var StatLabels = []string{
	"pass_tcp",
	"pass_udp_whitelisted",
	"drop_udp_not_whitelisted",
	"drop_udp_expired",
	"drop_malformed",
	"tcp_established_inserts",
	"tcp_l7_promoted",
	"tcp_l7_match_no_est",
	"drop_udp_ratelimit",
	"drop_tcp_initconnect_ratelimit",
	"drop_udp_enet_malformed",
	"drop_udp_unhealthy",
	"tcp_post_client_seen",
	"tcp_getinfo_seen",
	"drop_tcp_getinfo_ratelimit",
	"drop_tcp_bad_user_agent",
	"drop_tcp_no_syn",
	"drop_tcp_global_ratelimit",
	"drop_tcp_too_many_open",
}

const (
	StatPassTCP                     = 0
	StatPassUDPWhitelisted          = 1
	StatDropUDPNotWhitelisted       = 2
	StatDropUDPExpired              = 3
	StatDropMalformed               = 4
	StatTCPEstablishedInserts       = 5
	StatTCPL7Promoted               = 6
	StatTCPL7MatchNoEst             = 7
	StatDropUDPRatelimit            = 8
	StatDropTCPInitconnectRatelimit = 9
	StatDropUDPEnetMalformed        = 10
	StatDropUDPUnhealthy            = 11
	StatTCPPostClientSeen           = 12
	StatTCPGetinfoSeen              = 13
	StatDropTCPGetinfoRatelimit     = 14
	StatDropTCPBadUserAgent         = 15
	StatDropTCPNoSyn                = 16
	StatDropTCPGlobalRatelimit      = 17
	StatDropTCPTooManyOpen          = 18
)

var DropReasonNames = [12]string{
	"tcp_no_syn",
	"tcp_too_many_open",
	"tcp_global_ratelimit",
	"tcp_bad_user_agent",
	"tcp_initconnect_ratelimit",
	"tcp_getinfo_ratelimit",
	"malformed",
	"udp_not_whitelisted",
	"udp_expired",
	"udp_unhealthy",
	"udp_enet_malformed",
	"udp_ratelimit",
}
