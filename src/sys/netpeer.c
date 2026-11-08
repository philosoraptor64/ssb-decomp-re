#include <sys/netpeer.h>

#include <ft/fighter.h>
#include <gr/ground.h>
#include <sc/scmanager.h>
#include <sys/netinput.h>
#include <sys/netreplay.h>
#include <sys/netsync.h>
#include <sys/utils.h>

#ifdef PORT
extern char *getenv(const char *name);
extern int atoi(const char *s);
extern void port_log(const char *fmt, ...);
extern void port_watchdog_note_yield(void);
#if defined(PORT) && !defined(_WIN32)
struct sockaddr_in;
// port/net: find the peer through the n64net rendezvous server
// (SSB64_NETPLAY_SERVER / SSB64_NETPLAY_ROOM). Returns 0 on success.
extern int port_netplay_rendezvous(int sock, int is_host, struct sockaddr_in *out_peer);
// port/net: one step of a start-up wait that keeps the app responsive, and
// the "connecting" status shown meanwhile (NULL title hides it).
extern void port_netplay_boot_wait(void);
extern void port_netplay_status(const char *title, const char *text);
extern void port_netplay_alert(const char *text);
extern void port_netplay_rendezvous_bye(int sock);
#endif
#endif

#if defined(PORT) && !defined(_WIN32)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#endif

#define SYNETPEER_MAGIC 0x53534E50 // SSNP
#define SYNETPEER_VERSION 2
#define SYNETPEER_MAX_PACKET_FRAMES 16
#define SYNETPEER_FRAME_BYTES 8
#define SYNETPEER_INPUT_HEADER_BYTES (4 + 2 + 2 + 4 + 4 + 4 + 1 + 1 + 1 + 1)
#define SYNETPEER_PACKET_BYTES ((SYNETPEER_INPUT_HEADER_BYTES) + ((SYNETPEER_MAX_PACKET_FRAMES) * (SYNETPEER_FRAME_BYTES)) + 4)
#define SYNETPEER_VALIDATION_INPUT_WINDOW 120
#define SYNETPEER_METADATA_BYTES (11 * 4 + 8 + (MAXCONTROLLERS * 7))
#define SYNETPEER_BOOTSTRAP_PACKET_BYTES (4 + 2 + 2 + 4 + SYNETPEER_METADATA_BYTES + 4)
#define SYNETPEER_CONTROL_PACKET_BYTES (4 + 2 + 2 + 4 + 4)
#if defined(PORT) && !defined(_WIN32)
void syNetPeerHandleTimingPacket(const u8 *buffer, s32 size);
#endif
#define SYNETPEER_DEFAULT_INPUT_DELAY 2
#define SYNETPEER_DEFAULT_SESSION_ID 1
#define SYNETPEER_DEFAULT_BOOTSTRAP_SEED 12345
#define SYNETPEER_LOG_INTERVAL 120
#define SYNETPEER_BOOTSTRAP_RETRY_COUNT 300
// Waiting for the other instance to boot can take far longer than the
// handshake itself (two processes launched together reach this point up to
// ~15s apart on macOS), so the first wait gets its own ~60s budget.
#define SYNETPEER_BOOTSTRAP_PEER_WAIT_COUNT 3600
#define SYNETPEER_LOCKSTEP_POLL_USECS 500
#define SYNETPEER_LOCKSTEP_RESEND_USECS 4000
#define SYNETPEER_LOCKSTEP_TIMEOUT_USECS 5000000
#define SYNETPEER_SIM_QUEUE_LENGTH 256
#define SYNETPEER_BOOTSTRAP_RETRY_USECS 16666
#define SYNETPEER_BARRIER_LOG_INTERVAL 30
#define SYNETPEER_BATTLE_START_REPEAT_FRAMES 30

#define SYNETPEER_PACKET_INPUT 0
#define SYNETPEER_PACKET_MATCH_CONFIG 1
#define SYNETPEER_PACKET_READY 2
#define SYNETPEER_PACKET_START 3
#define SYNETPEER_PACKET_BATTLE_READY 4
#define SYNETPEER_PACKET_BATTLE_START 5
#define SYNETPEER_PACKET_PING 6
#define SYNETPEER_PACKET_PONG 7
#define SYNETPEER_TIMING_PACKET_BYTES (4 + 2 + 2 + 4 + 4 + 4 + 4)
// Online sessions ("connected as if local"): the host's save data for the
// session (unlocks, records, settings), sent during the handshake.
#define SYNETPEER_PACKET_SESSION_DATA 8
// Gameplay settings snapshot (port/net/netplay_settings.cpp): 16 x s32.
#define SYNETPEER_SESSION_SETTINGS_COUNT 16
extern void port_netplay_settings_capture(s32 *out);
extern void port_netplay_settings_begin(const s32 *values);
extern void port_netplay_settings_end(void);
#define SYNETPEER_SESSION_DATA_PACKET_BYTES (4 + 2 + 2 + 4 + 4 + sizeof(LBBackupData) + (4 * SYNETPEER_SESSION_SETTINGS_COUNT) + 4)
#define SYNETPEER_SESSION_LOCKSTEP_GIVEUP_USECS 30000000  // peer silent this long: end the session
// Live desync detection: both machines send their state fingerprints (menu
// SessionSync, battle fighter checkpoints) and compare them with their own.
#define SYNETPEER_PACKET_SYNC_CHECK 9
#define SYNETPEER_SYNC_CHECK_PACKET_BYTES (4 + 2 + 2 + 4 + 4 + 4 + 4 + 4)
#define SYNETPEER_SYNC_CHECK_RING 32
#define SYNETPEER_PING_INTERVAL 15 // ticks between round-trip probes

typedef struct SYNetPeerPacketFrame
{
	u32 tick;
	u16 buttons;
	s8 stick_x;
	s8 stick_y;

} SYNetPeerPacketFrame;

sb32 sSYNetPeerIsEnabled;
sb32 sSYNetPeerIsConfigured;
sb32 sSYNetPeerIsActive;
s32 sSYNetPeerLocalPlayer;
s32 sSYNetPeerRemotePlayer;
u32 sSYNetPeerInputDelay;
u32 sSYNetPeerSessionID;
u32 sSYNetPeerHighestRemoteTick;
u32 sSYNetPeerPacketsSent;
u32 sSYNetPeerPacketsReceived;
u32 sSYNetPeerPacketsDropped;
u32 sSYNetPeerFramesStaged;
u32 sSYNetPeerLateFrames;
u32 sSYNetPeerInputChecksum;
sb32 sSYNetPeerDebugBotIsEnabled;
sb32 sSYNetPeerLockstepIsEnabled;
// Rollback mode: remote input is predicted and corrected by port/rollback;
// the game only waits when the peer falls more than the window behind.
sb32 sSYNetPeerRollbackIsEnabled;
u32 sSYNetPeerRollbackWindow;
// Fighter hash after each simulated tick (resimulations overwrite), so
// NetSync checkpoints can be logged once their inputs are all confirmed.
#define SYNETPEER_TICK_HASH_RING 256
u32 sSYNetPeerTickHash[SYNETPEER_TICK_HASH_RING];
u32 sSYNetPeerTickHashTick[SYNETPEER_TICK_HASH_RING];
u32 sSYNetPeerNextCheckpointTick;
extern sb32 sSYNetPeerRemoteAdvantageValid; // time sync, defined with the timing packets
extern u32 sSYNetPeerTimeSyncSkips;
extern u32 sSYNetPeerTimeSyncCooldown;
extern s32 sSYNetPeerTimeSyncAhead16;
u32 sSYNetPeerStallTicks;
u32 sSYNetPeerStallUsecs;
u32 sSYNetPeerStallTimeouts;
// Debug network simulator for input packets (SSB64_NETPLAY_SIM_*).
u32 sSYNetPeerSimLossPercent;
u32 sSYNetPeerSimLatencyUsecs;
u32 sSYNetPeerSimJitterUsecs;
u32 sSYNetPeerSimRandom;
u32 sSYNetPeerSimDropped;
u32 sSYNetPeerLastLogTick;
u32 sSYNetPeerSendSeq;
u32 sSYNetPeerRecvSeqHighWater;
sb32 sSYNetPeerRecvSeqInitialized;
u32 sSYNetPeerSeqGaps;
u32 sSYNetPeerSeqDuplicates;
u32 sSYNetPeerSeqOutOfOrder;
u32 sSYNetPeerLastPeerAckTick;
u32 sSYNetPeerLastPacketOldestTick;
u32 sSYNetPeerLastPacketNewestTick;
sb32 sSYNetPeerLastPacketTicksValid;
sb32 sSYNetPeerBootstrapIsEnabled;
sb32 sSYNetPeerBootstrapIsHost;
sb32 sSYNetPeerBootstrapMetadataApplied;
sb32 sSYNetPeerBootstrapPeerReady;
sb32 sSYNetPeerBootstrapStartReceived;
u32 sSYNetPeerBootstrapSeed;
SYNetInputReplayMetadata sSYNetPeerBootstrapMetadata;
sb32 sSYNetPeerBattleBarrierEnabled;
sb32 sSYNetPeerBattleLocalReady;
sb32 sSYNetPeerBattlePeerReady;
sb32 sSYNetPeerBattleStartSent;
sb32 sSYNetPeerBattleStartReceived;
sb32 sSYNetPeerBattleBarrierReleased;
u32 sSYNetPeerBattleBarrierWaitFrames;
u32 sSYNetPeerBattleStartRepeatFrames;
u32 sSYNetPeerExecutionHoldFrames;
sb32 sSYNetPeerExecutionBeginLogged;

#if defined(PORT) && !defined(_WIN32)
sb32 sSYNetPeerUseRendezvous;
// Host-set-up matches (SSB64_NETPLAY_LOBBY=1): the host picks fighters, CPUs,
// teams, rules and stage in the normal VS menus; when the battle would start
// the room opens and the joiner plays player 2. One connection per match.
sb32 sSYNetPeerLobbyIsEnabled;
sb32 sSYNetPeerLobbyMatchOnline;  // this match is being played online
sb32 sSYNetPeerLobbyHasMetadata;  // host: config captured from the menus
// Online session (SSB64_NETPLAY_MODE=session): connected at launch, then the
// whole game (menus, battles, results) runs on both machines from the same
// inputs, as if both controllers were plugged into one console. One
// continuous netinput tick for the session; lockstep outside battles,
// rollback (if enabled) inside them.
sb32 sSYNetPeerSessionIsEnabled;
sb32 sSYNetPeerSessionIsActive;
sb32 sSYNetPeerSessionDataReceived;
LBBackupData sSYNetPeerSessionBackup;
s32 sSYNetPeerSessionSettings[SYNETPEER_SESSION_SETTINGS_COUNT];
u32 sSYNetPeerSessionRandom;
sb32 sSYNetPeerSessionRollbackArmed;  // rollback configured: used inside session battles
// Recent fingerprints (tick, kind, hash) from this machine and the peer.
u32 sSYNetPeerSyncLocalTick[SYNETPEER_SYNC_CHECK_RING], sSYNetPeerSyncLocalKind[SYNETPEER_SYNC_CHECK_RING], sSYNetPeerSyncLocalHash[SYNETPEER_SYNC_CHECK_RING];
u32 sSYNetPeerSyncRemoteTick[SYNETPEER_SYNC_CHECK_RING], sSYNetPeerSyncRemoteKind[SYNETPEER_SYNC_CHECK_RING], sSYNetPeerSyncRemoteHash[SYNETPEER_SYNC_CHECK_RING];
u32 sSYNetPeerSyncComparedTick[SYNETPEER_SYNC_CHECK_RING];
u32 sSYNetPeerSyncChecksMatched;
sb32 sSYNetPeerDesyncReported;
void syNetPeerSyncCheckReset(void);
void syNetPeerSyncCheckRecord(u32 tick, u32 kind, u32 hash);
s32 sSYNetPeerSocket = -1;
struct sockaddr_in sSYNetPeerBindAddress;
struct sockaddr_in sSYNetPeerPeerAddress;
#endif

u32 syNetPeerChecksumAccumulateU32(u32 checksum, u32 value)
{
	checksum ^= value;
	checksum *= 16777619U;

	return checksum;
}

u32 syNetPeerChecksumAccumulateFrame(u32 checksum, const SYNetPeerPacketFrame *frame)
{
	checksum = syNetPeerChecksumAccumulateU32(checksum, frame->tick);
	checksum = syNetPeerChecksumAccumulateU32(checksum, frame->buttons);
	checksum = syNetPeerChecksumAccumulateU32(checksum, (u8)frame->stick_x);
	checksum = syNetPeerChecksumAccumulateU32(checksum, (u8)frame->stick_y);

	return checksum;
}

u32 syNetPeerChecksumPacket(u32 session_id, u32 ack_tick, u32 packet_seq, u8 player, u8 frame_count, const SYNetPeerPacketFrame *frames)
{
	u32 checksum = 2166136261U;
	s32 i;

	checksum = syNetPeerChecksumAccumulateU32(checksum, SYNETPEER_MAGIC);
	checksum = syNetPeerChecksumAccumulateU32(checksum, SYNETPEER_VERSION);
	checksum = syNetPeerChecksumAccumulateU32(checksum, SYNETPEER_PACKET_INPUT);
	checksum = syNetPeerChecksumAccumulateU32(checksum, session_id);
	checksum = syNetPeerChecksumAccumulateU32(checksum, ack_tick);
	checksum = syNetPeerChecksumAccumulateU32(checksum, packet_seq);
	checksum = syNetPeerChecksumAccumulateU32(checksum, player);
	checksum = syNetPeerChecksumAccumulateU32(checksum, frame_count);

	for (i = 0; i < frame_count; i++)
	{
		checksum = syNetPeerChecksumAccumulateFrame(checksum, &frames[i]);
	}
	return checksum;
}

u32 syNetPeerChecksumBytes(const u8 *bytes, u32 size)
{
	u32 checksum = 2166136261U;
	u32 i;

	for (i = 0; i < size; i++)
	{
		checksum ^= bytes[i];
		checksum *= 16777619U;
	}
	return checksum;
}

void syNetPeerWriteU8(u8 **cursor, u8 value)
{
	*(*cursor)++ = value;
}

void syNetPeerWriteU16(u8 **cursor, u16 value)
{
	*(*cursor)++ = (value >> 8) & 0xFF;
	*(*cursor)++ = value & 0xFF;
}

void syNetPeerWriteU32(u8 **cursor, u32 value)
{
	*(*cursor)++ = (value >> 24) & 0xFF;
	*(*cursor)++ = (value >> 16) & 0xFF;
	*(*cursor)++ = (value >> 8) & 0xFF;
	*(*cursor)++ = value & 0xFF;
}

u8 syNetPeerReadU8(const u8 **cursor)
{
	return *(*cursor)++;
}

u16 syNetPeerReadU16(const u8 **cursor)
{
	u16 value = (u16)(*(*cursor)++) << 8;

	value |= *(*cursor)++;

	return value;
}

u32 syNetPeerReadU32(const u8 **cursor)
{
	u32 value = (u32)(*(*cursor)++) << 24;

	value |= (u32)(*(*cursor)++) << 16;
	value |= (u32)(*(*cursor)++) << 8;
	value |= *(*cursor)++;

	return value;
}

void syNetPeerWriteMetadata(u8 **cursor, const SYNetInputReplayMetadata *metadata)
{
	s32 player;

	syNetPeerWriteU32(cursor, metadata->magic);
	syNetPeerWriteU32(cursor, metadata->version);
	syNetPeerWriteU32(cursor, metadata->scene_kind);
	syNetPeerWriteU32(cursor, metadata->player_count);
	syNetPeerWriteU32(cursor, metadata->stage_kind);
	syNetPeerWriteU32(cursor, metadata->stocks);
	syNetPeerWriteU32(cursor, metadata->time_limit);
	syNetPeerWriteU32(cursor, metadata->item_switch);
	syNetPeerWriteU32(cursor, metadata->item_toggles);
	syNetPeerWriteU32(cursor, metadata->rng_seed);
	syNetPeerWriteU32(cursor, metadata->game_type);
	syNetPeerWriteU8(cursor, metadata->game_rules);
	syNetPeerWriteU8(cursor, metadata->is_team_battle);
	syNetPeerWriteU8(cursor, metadata->handicap);
	syNetPeerWriteU8(cursor, metadata->is_team_attack);
	syNetPeerWriteU8(cursor, metadata->is_stage_select);
	syNetPeerWriteU8(cursor, metadata->damage_ratio);
	syNetPeerWriteU8(cursor, metadata->item_appearance_rate);
	syNetPeerWriteU8(cursor, metadata->is_not_teamshadows);

	for (player = 0; player < MAXCONTROLLERS; player++)
	{
		syNetPeerWriteU8(cursor, metadata->player_kinds[player]);
		syNetPeerWriteU8(cursor, metadata->fighter_kinds[player]);
		syNetPeerWriteU8(cursor, metadata->costumes[player]);
		syNetPeerWriteU8(cursor, metadata->teams[player]);
		syNetPeerWriteU8(cursor, metadata->handicaps[player]);
		syNetPeerWriteU8(cursor, metadata->levels[player]);
		syNetPeerWriteU8(cursor, metadata->shades[player]);
	}
}

void syNetPeerReadMetadata(const u8 **cursor, SYNetInputReplayMetadata *metadata)
{
	s32 player;

	metadata->magic = syNetPeerReadU32(cursor);
	metadata->version = syNetPeerReadU32(cursor);
	metadata->scene_kind = syNetPeerReadU32(cursor);
	metadata->player_count = syNetPeerReadU32(cursor);
	metadata->stage_kind = syNetPeerReadU32(cursor);
	metadata->stocks = syNetPeerReadU32(cursor);
	metadata->time_limit = syNetPeerReadU32(cursor);
	metadata->item_switch = syNetPeerReadU32(cursor);
	metadata->item_toggles = syNetPeerReadU32(cursor);
	metadata->rng_seed = syNetPeerReadU32(cursor);
	metadata->game_type = syNetPeerReadU32(cursor);
	metadata->game_rules = syNetPeerReadU8(cursor);
	metadata->is_team_battle = syNetPeerReadU8(cursor);
	metadata->handicap = syNetPeerReadU8(cursor);
	metadata->is_team_attack = syNetPeerReadU8(cursor);
	metadata->is_stage_select = syNetPeerReadU8(cursor);
	metadata->damage_ratio = syNetPeerReadU8(cursor);
	metadata->item_appearance_rate = syNetPeerReadU8(cursor);
	metadata->is_not_teamshadows = syNetPeerReadU8(cursor);

	for (player = 0; player < MAXCONTROLLERS; player++)
	{
		metadata->player_kinds[player] = syNetPeerReadU8(cursor);
		metadata->fighter_kinds[player] = syNetPeerReadU8(cursor);
		metadata->costumes[player] = syNetPeerReadU8(cursor);
		metadata->teams[player] = syNetPeerReadU8(cursor);
		metadata->handicaps[player] = syNetPeerReadU8(cursor);
		metadata->levels[player] = syNetPeerReadU8(cursor);
		metadata->shades[player] = syNetPeerReadU8(cursor);
	}
}

sb32 syNetPeerCheckMetadata(const SYNetInputReplayMetadata *metadata)
{
	if ((metadata->magic != SYNETINPUT_REPLAY_MAGIC) ||
		(metadata->version != SYNETINPUT_REPLAY_VERSION) ||
		(metadata->scene_kind != nSCKindVSBattle) ||
		(metadata->player_count == 0) ||
		(metadata->player_count > MAXCONTROLLERS))
	{
		return FALSE;
	}
	return TRUE;
}

#if defined(PORT) && !defined(_WIN32)
void syNetPeerSleepBootstrapRetry(void)
{
	// Hands the frame back to the main loop (~16 ms per step) instead of
	// blocking it, so the OS keeps getting answers while we wait for the
	// peer (iOS kills apps that stop responding); also pets the watchdog.
	port_netplay_boot_wait();
}

const char *syNetPeerFindPortSeparator(const char *text)
{
	const char *separator = NULL;

	while (*text != '\0')
	{
		if (*text == ':')
		{
			separator = text;
		}
		text++;
	}
	return separator;
}

sb32 syNetPeerStringEquals(const char *a, const char *b)
{
	while ((*a != '\0') && (*b != '\0'))
	{
		if (*a != *b)
		{
			return FALSE;
		}
		a++;
		b++;
	}
	return (*a == *b) ? TRUE : FALSE;
}

sb32 syNetPeerParseIPv4Address(const char *text, struct sockaddr_in *out_address)
{
	const char *colon;
	s32 host_length;
	s32 port;
	char host[64];

	if ((text == NULL) || (out_address == NULL))
	{
		return FALSE;
	}
	colon = syNetPeerFindPortSeparator(text);

	if ((colon == NULL) || (colon == text) || (*(colon + 1) == '\0'))
	{
		return FALSE;
	}
	host_length = colon - text;

	if (host_length >= (s32)sizeof(host))
	{
		return FALSE;
	}
	memcpy(host, text, host_length);
	host[host_length] = '\0';

	port = atoi(colon + 1);

	// Port 0 = any free port (binding), or "to be filled in" (room codes).
	if ((port < 0) || (port > 65535))
	{
		return FALSE;
	}
	memset(out_address, 0, sizeof(*out_address));
	out_address->sin_family = AF_INET;
	out_address->sin_port = htons((u16)port);

	if ((syNetPeerStringEquals(host, "*") != FALSE) || (syNetPeerStringEquals(host, "0.0.0.0") != FALSE))
	{
		out_address->sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else if (inet_pton(AF_INET, host, &out_address->sin_addr) != 1)
	{
		return FALSE;
	}
	return TRUE;
}

void syNetPeerCloseSocket(void)
{
	if (sSYNetPeerSocket >= 0)
	{
		close(sSYNetPeerSocket);
		sSYNetPeerSocket = -1;
	}
}

sb32 syNetPeerOpenSocket(void)
{
	s32 flags;
	s32 reuse = 1;

	if (sSYNetPeerSocket >= 0)
	{
		return TRUE;
	}
	sSYNetPeerSocket = socket(AF_INET, SOCK_DGRAM, 0);

	if (sSYNetPeerSocket < 0)
	{
		port_log("SSB64 NetPeer: socket failed errno=%d\n", errno);
		return FALSE;
	}
	setsockopt(sSYNetPeerSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	// Ask for low-latency treatment (Wi-Fi WMM voice queue): input packets
	// are tiny and time-critical. SSB64_NETPLAY_QOS=0 turns it off for A/B
	// tests.
	if ((getenv("SSB64_NETPLAY_QOS") == NULL) || (atoi(getenv("SSB64_NETPLAY_QOS")) != 0))
	{
		s32 tos = 0xB8; // DSCP EF
#ifdef SO_NET_SERVICE_TYPE
		s32 service = NET_SERVICE_TYPE_VO;

		setsockopt(sSYNetPeerSocket, SOL_SOCKET, SO_NET_SERVICE_TYPE, &service, sizeof(service));
#endif
#ifdef IP_TOS
		setsockopt(sSYNetPeerSocket, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
		(void)tos;
		port_log("SSB64 NetPeer: low-latency QoS requested\n");
	}

	if (bind(sSYNetPeerSocket, (struct sockaddr*)&sSYNetPeerBindAddress, sizeof(sSYNetPeerBindAddress)) != 0)
	{
		port_log("SSB64 NetPeer: bind failed errno=%d\n", errno);
		syNetPeerCloseSocket();
		return FALSE;
	}
	flags = fcntl(sSYNetPeerSocket, F_GETFL, 0);

	if ((flags < 0) || (fcntl(sSYNetPeerSocket, F_SETFL, flags | O_NONBLOCK) != 0))
	{
		port_log("SSB64 NetPeer: nonblocking setup failed errno=%d\n", errno);
		syNetPeerCloseSocket();
		return FALSE;
	}
	return TRUE;
}
#endif

// Fighter for a player from SSB64_NETPLAY_P<n>_FIGHTER (a name such as
// "kirby", or the FTKind number). The host's choice travels in the match
// config, so only the host's setting matters.
sb32 syNetPeerMatchesName(const char *value, const char *name)
{
	while ((*value != '\0') && (*name != '\0'))
	{
		if (tolower((unsigned char)*value) != *name)
		{
			return FALSE;
		}
		value++, name++;
	}
	return ((*value == '\0') && (*name == '\0')) ? TRUE : FALSE;
}

s32 syNetPeerGetBootstrapFighter(s32 player, s32 fallback)
{
	static const char *names[] = { "mario", "fox", "donkey", "samus", "luigi", "link",
	                               "yoshi", "captain", "kirby", "pikachu", "purin", "ness" };
	char key[] = "SSB64_NETPLAY_Pn_FIGHTER";
	const char *value;
	s32 i;

	key[sizeof("SSB64_NETPLAY_P") - 1] = (char)('1' + player);
	value = getenv(key);

	if (value == NULL)
	{
		return fallback;
	}
	for (i = 0; i < (s32)ARRAY_COUNT(names); i++)
	{
		if (syNetPeerMatchesName(value, names[i]) != FALSE)
		{
			return nFTKindPlayableStart + i;
		}
	}
	if ((atoi(value) >= nFTKindPlayableStart) && (atoi(value) <= nFTKindPlayableEnd))
	{
		return atoi(value);
	}
	return fallback;
}

void syNetPeerMakeBootstrapMetadata(SYNetInputReplayMetadata *metadata)
{
	s32 player;

	memset(metadata, 0, sizeof(*metadata));
	metadata->magic = SYNETINPUT_REPLAY_MAGIC;
	metadata->version = SYNETINPUT_REPLAY_VERSION;
	metadata->scene_kind = nSCKindVSBattle;
	metadata->player_count = 2;
	metadata->stage_kind = nGRKindCastle;
	metadata->stocks = 3;
	metadata->time_limit = SCBATTLE_TIMELIMIT_INFINITE;
	metadata->item_switch = nSCBattleItemSwitchNone;
	metadata->item_toggles = 0;
	metadata->rng_seed = sSYNetPeerBootstrapSeed;
	metadata->game_type = nSCBattleGameTypeRoyal;
	metadata->game_rules = SCBATTLE_GAMERULE_STOCK;
	metadata->is_team_battle = FALSE;
	metadata->handicap = nSCBattleHandicapOff;
	metadata->is_team_attack = FALSE;
	metadata->is_stage_select = FALSE;
	metadata->damage_ratio = 100;
	metadata->item_appearance_rate = nSCBattleItemSwitchNone;
	metadata->is_not_teamshadows = TRUE;

	for (player = 0; player < MAXCONTROLLERS; player++)
	{
		metadata->player_kinds[player] = nFTPlayerKindNot;
		metadata->fighter_kinds[player] = nFTKindNull;
		metadata->costumes[player] = 0;
		metadata->teams[player] = player;
		metadata->handicaps[player] = 9;
		metadata->levels[player] = 3;
		metadata->shades[player] = 0;
	}
	metadata->player_kinds[0] = nFTPlayerKindMan;
	metadata->fighter_kinds[0] = syNetPeerGetBootstrapFighter(0, nFTKindMario);
	metadata->player_kinds[1] = nFTPlayerKindMan;
	metadata->fighter_kinds[1] = syNetPeerGetBootstrapFighter(1, nFTKindFox);

	// SSB64_NETPLAY_P<n>_CPU=<level 1-9> makes that player the game's own
	// computer opponent. The AI runs inside the simulation on both machines,
	// so it needs no network input and rollback simply recomputes it.
	for (player = 0; player < 2; player++)
	{
		char key[] = "SSB64_NETPLAY_Pn_CPU";
		const char *value;

		key[sizeof("SSB64_NETPLAY_P") - 1] = (char)('1' + player);
		value = getenv(key);

		if ((value != NULL) && (atoi(value) >= 1) && (atoi(value) <= 9))
		{
			metadata->player_kinds[player] = nFTPlayerKindCom;
			metadata->levels[player] = atoi(value);
		}
	}
}

void syNetPeerApplyBootstrapMetadata(const SYNetInputReplayMetadata *metadata)
{
	sSYNetPeerBootstrapMetadata = *metadata;
	syNetReplayApplyBattleMetadata(&sSYNetPeerBootstrapMetadata);
	syUtilsSetRandomSeed(sSYNetPeerBootstrapMetadata.rng_seed);
	gSCManagerSceneData.scene_prev = nSCKindVSMode;
	gSCManagerSceneData.scene_curr = nSCKindVSBattle;
	sSYNetPeerBootstrapMetadataApplied = TRUE;

#ifdef PORT
	port_log("SSB64 NetPeer: bootstrap metadata applied host=%d stage=%u seed=%u players=%u p0=%u/%u p1=%u/%u\n",
	         sSYNetPeerBootstrapIsHost, sSYNetPeerBootstrapMetadata.stage_kind,
	         sSYNetPeerBootstrapMetadata.rng_seed, sSYNetPeerBootstrapMetadata.player_count,
	         sSYNetPeerBootstrapMetadata.player_kinds[0], sSYNetPeerBootstrapMetadata.fighter_kinds[0],
	         sSYNetPeerBootstrapMetadata.player_kinds[1], sSYNetPeerBootstrapMetadata.fighter_kinds[1]);
#endif
}

#if defined(PORT) && !defined(_WIN32)
void syNetPeerSendBytes(const u8 *buffer, u32 size)
{
	sendto(sSYNetPeerSocket, buffer, size, 0,
	       (struct sockaddr*)&sSYNetPeerPeerAddress, sizeof(sSYNetPeerPeerAddress));
}
#endif

void syNetPeerSendControlPacket(u16 packet_type)
{
#if defined(PORT) && !defined(_WIN32)
	u8 buffer[SYNETPEER_CONTROL_PACKET_BYTES];
	u8 *cursor = buffer;
	u32 checksum;

	syNetPeerWriteU32(&cursor, SYNETPEER_MAGIC);
	syNetPeerWriteU16(&cursor, SYNETPEER_VERSION);
	syNetPeerWriteU16(&cursor, packet_type);
	syNetPeerWriteU32(&cursor, sSYNetPeerSessionID);
	checksum = syNetPeerChecksumBytes(buffer, cursor - buffer);
	syNetPeerWriteU32(&cursor, checksum);
	syNetPeerSendBytes(buffer, SYNETPEER_CONTROL_PACKET_BYTES);
#endif
}

#if defined(PORT) && !defined(_WIN32)
void syNetPeerSendMatchConfigPacket(void)
{
	u8 buffer[SYNETPEER_BOOTSTRAP_PACKET_BYTES];
	u8 *cursor = buffer;
	u32 checksum;

	syNetPeerWriteU32(&cursor, SYNETPEER_MAGIC);
	syNetPeerWriteU16(&cursor, SYNETPEER_VERSION);
	syNetPeerWriteU16(&cursor, SYNETPEER_PACKET_MATCH_CONFIG);
	syNetPeerWriteU32(&cursor, sSYNetPeerSessionID);
	syNetPeerWriteMetadata(&cursor, &sSYNetPeerBootstrapMetadata);
	checksum = syNetPeerChecksumBytes(buffer, cursor - buffer);
	syNetPeerWriteU32(&cursor, checksum);
	syNetPeerSendBytes(buffer, SYNETPEER_BOOTSTRAP_PACKET_BYTES);
}

void syNetPeerHandleControlPacket(const u8 *buffer, s32 size)
{
	const u8 *cursor = buffer;
	u32 magic;
	u32 session_id;
	u32 checksum;
	u32 expected_checksum;
	u16 version;
	u16 packet_type;

	if (size != SYNETPEER_CONTROL_PACKET_BYTES)
	{
		return;
	}
	expected_checksum = syNetPeerChecksumBytes(buffer, SYNETPEER_CONTROL_PACKET_BYTES - 4);

	magic = syNetPeerReadU32(&cursor);
	version = syNetPeerReadU16(&cursor);
	packet_type = syNetPeerReadU16(&cursor);
	session_id = syNetPeerReadU32(&cursor);
	checksum = syNetPeerReadU32(&cursor);

	if ((magic != SYNETPEER_MAGIC) || (version != SYNETPEER_VERSION) ||
		(session_id != sSYNetPeerSessionID) || (checksum != expected_checksum))
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	if (packet_type == SYNETPEER_PACKET_READY)
	{
		sSYNetPeerBootstrapPeerReady = TRUE;
	}
	else if (packet_type == SYNETPEER_PACKET_START)
	{
		sSYNetPeerBootstrapStartReceived = TRUE;
	}
	else if (packet_type == SYNETPEER_PACKET_BATTLE_READY)
	{
		if (sSYNetPeerBattlePeerReady == FALSE)
		{
			port_log("SSB64 NetPeer: received BATTLE_READY role=%s tick=%u local=%d remote=%d\n",
			         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
			         syNetInputGetTick(), sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer);
		}
		sSYNetPeerBattlePeerReady = TRUE;
	}
	else if (packet_type == SYNETPEER_PACKET_BATTLE_START)
	{
		if (sSYNetPeerBattleStartReceived == FALSE)
		{
			port_log("SSB64 NetPeer: received BATTLE_START role=%s tick=%u local=%d remote=%d\n",
			         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
			         syNetInputGetTick(), sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer);
		}
		sSYNetPeerBattleStartReceived = TRUE;
	}
}

void syNetPeerHandleMatchConfigPacket(const u8 *buffer, s32 size)
{
	const u8 *cursor = buffer;
	SYNetInputReplayMetadata metadata;
	u32 magic;
	u32 session_id;
	u32 checksum;
	u32 expected_checksum;
	u16 version;
	u16 packet_type;

	if (size != SYNETPEER_BOOTSTRAP_PACKET_BYTES)
	{
		return;
	}
	expected_checksum = syNetPeerChecksumBytes(buffer, SYNETPEER_BOOTSTRAP_PACKET_BYTES - 4);

	magic = syNetPeerReadU32(&cursor);
	version = syNetPeerReadU16(&cursor);
	packet_type = syNetPeerReadU16(&cursor);
	session_id = syNetPeerReadU32(&cursor);
	syNetPeerReadMetadata(&cursor, &metadata);
	checksum = syNetPeerReadU32(&cursor);

	if ((magic != SYNETPEER_MAGIC) || (version != SYNETPEER_VERSION) ||
		(packet_type != SYNETPEER_PACKET_MATCH_CONFIG) ||
		(session_id != sSYNetPeerSessionID) || (checksum != expected_checksum) ||
		(syNetPeerCheckMetadata(&metadata) == FALSE))
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	if (sSYNetPeerBootstrapIsHost == FALSE)
	{
		syNetPeerApplyBootstrapMetadata(&metadata);
	}
}

// Host -> joiner: the save data and gameplay settings both machines use
// during the session.
void syNetPeerSendSessionDataPacket(void)
{
	u8 buffer[SYNETPEER_SESSION_DATA_PACKET_BYTES];
	u8 *cursor = buffer;
	u32 checksum;
	s32 i;

	syNetPeerWriteU32(&cursor, SYNETPEER_MAGIC);
	syNetPeerWriteU16(&cursor, SYNETPEER_VERSION);
	syNetPeerWriteU16(&cursor, SYNETPEER_PACKET_SESSION_DATA);
	syNetPeerWriteU32(&cursor, sSYNetPeerSessionID);
	syNetPeerWriteU32(&cursor, (u32)sizeof(LBBackupData));
	memcpy(cursor, &gSCManagerBackupData, sizeof(LBBackupData));
	cursor += sizeof(LBBackupData);
	port_netplay_settings_capture(sSYNetPeerSessionSettings);
	for (i = 0; i < SYNETPEER_SESSION_SETTINGS_COUNT; i++)
	{
		syNetPeerWriteU32(&cursor, (u32)sSYNetPeerSessionSettings[i]);
	}
	checksum = syNetPeerChecksumBytes(buffer, cursor - buffer);
	syNetPeerWriteU32(&cursor, checksum);
	syNetPeerSendBytes(buffer, sizeof(buffer));
}

void syNetPeerHandleSessionDataPacket(const u8 *buffer, s32 size)
{
	const u8 *cursor = buffer;
	const u8 *trailer = buffer + size - 4;
	u32 length;

	if ((syNetPeerReadU32(&cursor) != SYNETPEER_MAGIC) || (syNetPeerReadU16(&cursor) != SYNETPEER_VERSION) ||
		(syNetPeerReadU16(&cursor) != SYNETPEER_PACKET_SESSION_DATA) || (syNetPeerReadU32(&cursor) != sSYNetPeerSessionID))
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	length = syNetPeerReadU32(&cursor);

	if ((length != sizeof(LBBackupData)) || (syNetPeerChecksumBytes(buffer, size - 4) != syNetPeerReadU32(&trailer)))
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	memcpy(&sSYNetPeerSessionBackup, cursor, sizeof(LBBackupData));
	cursor += sizeof(LBBackupData);
	{
		s32 i;

		for (i = 0; i < SYNETPEER_SESSION_SETTINGS_COUNT; i++)
		{
			sSYNetPeerSessionSettings[i] = (s32)syNetPeerReadU32(&cursor);
		}
	}
	sSYNetPeerSessionDataReceived = TRUE;
}

void syNetPeerHandleBootstrapPacket(const u8 *buffer, s32 size)
{
	if (size == SYNETPEER_CONTROL_PACKET_BYTES)
	{
		syNetPeerHandleControlPacket(buffer, size);
	}
	else if (size == SYNETPEER_BOOTSTRAP_PACKET_BYTES)
	{
		syNetPeerHandleMatchConfigPacket(buffer, size);
	}
	else if (size == SYNETPEER_TIMING_PACKET_BYTES)
	{
		syNetPeerHandleTimingPacket(buffer, size);
	}
	else if (size == (s32)SYNETPEER_SESSION_DATA_PACKET_BYTES)
	{
		syNetPeerHandleSessionDataPacket(buffer, size);
	}
	else sSYNetPeerPacketsDropped++;
}

void syNetPeerReceiveBootstrapPackets(void)
{
	// Big enough for every handshake packet (the session data is the largest).
	u8 buffer[(SYNETPEER_SESSION_DATA_PACKET_BYTES > SYNETPEER_BOOTSTRAP_PACKET_BYTES) ? SYNETPEER_SESSION_DATA_PACKET_BYTES
	                                                                                    : SYNETPEER_BOOTSTRAP_PACKET_BYTES];

	while (TRUE)
	{
		ssize_t size = recvfrom(sSYNetPeerSocket, buffer, sizeof(buffer), 0, NULL, NULL);

		if (size < 0)
		{
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
			{
				sSYNetPeerPacketsDropped++;
			}
			break;
		}
		syNetPeerHandleBootstrapPacket(buffer, (s32)size);
	}
}

void syNetPeerRunBootstrapSteps(void);

void syNetPeerRunBootstrap(void)
{
	syNetPeerRunBootstrapSteps();
	port_netplay_status(NULL, NULL);  // connected, failed or timed out: hide "connecting"
}

void syNetPeerRunBootstrapSteps(void)
{
	s32 i;

	if ((sSYNetPeerBootstrapIsEnabled == FALSE) || (sSYNetPeerIsConfigured == FALSE))
	{
		return;
	}
	if (syNetPeerOpenSocket() == FALSE)
	{
		return;
	}
	if ((sSYNetPeerUseRendezvous != FALSE) &&
		(port_netplay_rendezvous(sSYNetPeerSocket, sSYNetPeerBootstrapIsHost != FALSE, &sSYNetPeerPeerAddress) != 0))
	{
		port_log("SSB64 NetPeer: room-code connection failed; playing offline\n");
		syNetPeerCloseSocket();
		return;
	}
	sSYNetPeerIsActive = TRUE;

	if (sSYNetPeerBootstrapIsHost != FALSE)
	{
		if (sSYNetPeerLobbyHasMetadata == FALSE)
		{
			syNetPeerMakeBootstrapMetadata(&sSYNetPeerBootstrapMetadata);
		}
		syNetPeerApplyBootstrapMetadata(&sSYNetPeerBootstrapMetadata);

		for (i = 0; i < SYNETPEER_BOOTSTRAP_PEER_WAIT_COUNT; i++)
		{
			syNetPeerSendMatchConfigPacket();
			if ((sSYNetPeerSessionIsEnabled != FALSE) && ((i % 4) == 0))
			{
				syNetPeerSendSessionDataPacket();
			}
			syNetPeerReceiveBootstrapPackets();

			if (sSYNetPeerBootstrapPeerReady != FALSE)
			{
				break;
			}
			syNetPeerSleepBootstrapRetry();
		}
		if (sSYNetPeerBootstrapPeerReady == FALSE)
		{
			port_log("SSB64 NetPeer: bootstrap host timed out waiting for READY\n");
			return;
		}
		for (i = 0; i < 30; i++)
		{
			syNetPeerSendControlPacket(SYNETPEER_PACKET_START);
			syNetPeerSleepBootstrapRetry();
		}
		port_log("SSB64 NetPeer: bootstrap host sent START stage=%u seed=%u\n",
		         sSYNetPeerBootstrapMetadata.stage_kind, sSYNetPeerBootstrapMetadata.rng_seed);
	}
	else
	{
		for (i = 0; i < SYNETPEER_BOOTSTRAP_PEER_WAIT_COUNT; i++)
		{
			syNetPeerReceiveBootstrapPackets();

			if ((sSYNetPeerBootstrapMetadataApplied != FALSE) &&
				((sSYNetPeerSessionIsEnabled == FALSE) || (sSYNetPeerSessionDataReceived != FALSE)))
			{
				syNetPeerSendControlPacket(SYNETPEER_PACKET_READY);
				break;
			}
			syNetPeerSleepBootstrapRetry();
		}
		if (sSYNetPeerBootstrapMetadataApplied == FALSE)
		{
			port_log("SSB64 NetPeer: bootstrap client timed out waiting for MATCH_CONFIG\n");
			return;
		}
		for (i = 0; i < SYNETPEER_BOOTSTRAP_RETRY_COUNT; i++)
		{
			syNetPeerSendControlPacket(SYNETPEER_PACKET_READY);
			syNetPeerReceiveBootstrapPackets();

			if (sSYNetPeerBootstrapStartReceived != FALSE)
			{
				break;
			}
			syNetPeerSleepBootstrapRetry();
		}
		if (sSYNetPeerBootstrapStartReceived == FALSE)
		{
			port_log("SSB64 NetPeer: bootstrap client timed out waiting for START\n");
			return;
		}
		port_log("SSB64 NetPeer: bootstrap client received START stage=%u seed=%u\n",
		         sSYNetPeerBootstrapMetadata.stage_kind, sSYNetPeerBootstrapMetadata.rng_seed);
	}
}
#endif

#if defined(PORT) && !defined(_WIN32)
extern void syNetInputReset(void);
extern void syNetInputFuncRead(void);
extern void syNetInputSetLocalInputDelay(u32 delay);
extern void syNetPeerResetSessionCounters(void);

sb32 syNetPeerSessionCheckActive(void)
{
	return sSYNetPeerSessionIsActive;
}

// TRUE while this machine plays a session on the host's save data: it must
// not be written to this machine's save file (lb/lbbackup.c).
sb32 syNetPeerSessionCheckBorrowedSave(void)
{
	return ((sSYNetPeerSessionIsActive != FALSE) && (sSYNetPeerBootstrapIsHost == FALSE)) ? TRUE : FALSE;
}

// The menus' clock-based random picks during a session (sys/utils.c).
u32 syNetPeerSessionNextRandom(void)
{
	sSYNetPeerSessionRandom = (sSYNetPeerSessionRandom * 1103515245U) + 12345U;
	return sSYNetPeerSessionRandom >> 16;
}

// TRUE when the current scene runs a VS battle (rollback territory);
// everything else in a session runs in strict lockstep.
sb32 syNetPeerSessionCheckInBattle(void)
{
	return (gSCManagerSceneData.scene_curr == nSCKindVSBattle) ? TRUE : FALSE;
}

// After a successful handshake: start the session in the VS menu.
void syNetPeerSessionBegin(void)
{
	s32 player;

	if (sSYNetPeerBootstrapIsHost == FALSE)
	{
		// The host's unlocks, records and settings for the whole session
		// (never written to this machine's save: see lbBackupWrite).
		gSCManagerBackupData = sSYNetPeerSessionBackup;
	}
	else port_netplay_settings_capture(sSYNetPeerSessionSettings);  // the host: its own settings
	// Both use the host's gameplay settings until the session ends.
	port_netplay_settings_begin(sSYNetPeerSessionSettings);
	syNetInputReset();
	for (player = 0; player < MAXCONTROLLERS; player++)
	{
		syNetInputSetSlotSource(player, nSYNetInputSourceSaved);  // neutral unless a player below
	}
	syNetInputSetSlotSource(sSYNetPeerLocalPlayer, nSYNetInputSourceLocal);
	syNetInputSetSlotSource(sSYNetPeerRemotePlayer, nSYNetInputSourceRemotePredicted);
	syNetInputSetLocalInputDelay(sSYNetPeerInputDelay);
	syNetPeerResetSessionCounters();
	syNetPeerSyncCheckReset();

	sSYNetPeerIsActive = TRUE;
	sSYNetPeerBattleBarrierEnabled = FALSE;
	sSYNetPeerBattleBarrierReleased = TRUE;
	sSYNetPeerExecutionBeginLogged = TRUE;
	sSYNetPeerLockstepIsEnabled = TRUE;
	sSYNetPeerSessionRandom = sSYNetPeerBootstrapMetadata.rng_seed;
	sSYNetPeerSessionIsActive = TRUE;

	gSCManagerSceneData.scene_prev = nSCKindTitle;
	gSCManagerSceneData.scene_curr = nSCKindVSMode;
	if (getenv("SSB64_NETPLAY_SESSION_START_SCENE") != NULL)
	{
		// Unattended tests: start the session somewhere else (e.g. 22 = a VS
		// battle with the handshake's default players).
		gSCManagerSceneData.scene_prev = nSCKindVSMode;
		gSCManagerSceneData.scene_curr = atoi(getenv("SSB64_NETPLAY_SESSION_START_SCENE"));
	}
	port_netplay_status(NULL, NULL);
	port_log("SSB64 NetPeer: session started role=%s local=%d remote=%d delay=%u seed=%u backup=%u bytes "
	         "settings=%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
	         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "joiner", sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer,
	         sSYNetPeerInputDelay, sSYNetPeerSessionRandom, (u32)sizeof(LBBackupData),
	         sSYNetPeerSessionSettings[0], sSYNetPeerSessionSettings[1], sSYNetPeerSessionSettings[2],
	         sSYNetPeerSessionSettings[3], sSYNetPeerSessionSettings[4], sSYNetPeerSessionSettings[5],
	         sSYNetPeerSessionSettings[6], sSYNetPeerSessionSettings[7], sSYNetPeerSessionSettings[8],
	         sSYNetPeerSessionSettings[9], sSYNetPeerSessionSettings[10], sSYNetPeerSessionSettings[11]);
}

// The session ends (the peer is gone): both games carry on offline.
void syNetPeerSessionEnd(const char *reason)
{
	s32 player;

	if (sSYNetPeerSessionIsActive == FALSE)
	{
		return;
	}
	port_log("SSB64 NetPeer: session ended: %s\n", reason);
	sSYNetPeerSessionIsActive = FALSE;
	sSYNetPeerIsActive = FALSE;
	sSYNetPeerRollbackIsEnabled = FALSE;
	port_netplay_settings_end();
	syNetPeerCloseSocket();
	for (player = 0; player < MAXCONTROLLERS; player++)
	{
		syNetInputSetSlotSource(player, nSYNetInputSourceLocal);
	}
	port_netplay_alert("The online session ended (the other player left or the connection was lost). "
	                   "You can keep playing offline.");
}

// Fingerprint of the shared game state outside battles: both machines must
// produce the same value at the same tick (logged as SSB64 SessionSync).
u32 syNetPeerSessionHashState(void)
{
	SYNetInputReplayMetadata settings;
	u32 hash = 2166136261U;
	s32 player;

	syNetReplayCaptureBattleMetadata(&gSCManagerTransferBattleState, &settings);
	hash = syNetPeerChecksumAccumulateU32(hash, syNetInputGetTick());
	hash = syNetPeerChecksumAccumulateU32(hash, gSCManagerSceneData.scene_curr);
	hash = syNetPeerChecksumAccumulateU32(hash, gSCManagerSceneData.scene_prev);
	hash = syNetPeerChecksumAccumulateU32(hash, gSCManagerSceneData.gkind);
	hash = syNetPeerChecksumAccumulateU32(hash, sSYNetPeerSessionRandom);
	hash = syNetPeerChecksumAccumulateU32(hash, (u32)syUtilsRandSeed());  // the game's own RNG (read only)
	hash = syNetPeerChecksumAccumulateU32(hash, syNetPeerChecksumBytes((const u8 *)&settings, sizeof(settings)));
	for (player = 0; player < MAXCONTROLLERS; player++)
	{
		hash = syNetPeerChecksumAccumulateU32(hash, gSYControllerDevices[player].button_hold);
		hash = syNetPeerChecksumAccumulateU32(hash, (u8)gSYControllerDevices[player].stick_range.x);
		hash = syNetPeerChecksumAccumulateU32(hash, (u8)gSYControllerDevices[player].stick_range.y);
	}
	return hash;
}

// Controller read for every non-battle scene during a session
// (sys/controller.c): the same steps as a battle frame, in lockstep.
void syNetPeerSessionFuncRead(void)
{
	// Test hook: SSB64_NETPLAY_TEST_DESYNC=<tick> on one machine nudges its
	// session RNG at that tick, to check that the desync alert fires.
	if ((getenv("SSB64_NETPLAY_TEST_DESYNC") != NULL) && (syNetInputGetTick() == (u32)atoi(getenv("SSB64_NETPLAY_TEST_DESYNC"))))
	{
		sSYNetPeerSessionRandom++;
	}
	syNetInputFuncRead();
	syNetPeerUpdate();

	if ((syNetInputGetTick() % 120) == 0)
	{
		u32 hash = syNetPeerSessionHashState();

		port_log("SSB64 SessionSync: tick=%u scene=%u hash=%08X\n", syNetInputGetTick(), gSCManagerSceneData.scene_curr, hash);
		syNetPeerSyncCheckRecord(syNetInputGetTick(), 0, hash);
	}
}

// Called at the start of every VS battle scene (scVSBattleStartScene), before
// the battle reads gSCManagerTransferBattleState. Returns TRUE if the scene
// should be abandoned (the joiner gave up waiting; it goes to the title).
sb32 syNetPeerLobbyBeginMatch(void)
{
	SCBattleState menu_state = gSCManagerTransferBattleState;  // the host's choices, for an offline fallback

	sSYNetPeerLobbyMatchOnline = FALSE;
	sSYNetPeerLobbyHasMetadata = FALSE;

	if (sSYNetPeerLobbyIsEnabled == FALSE)
	{
		return FALSE;
	}
	sSYNetPeerIsEnabled = TRUE;
	sSYNetPeerIsActive = FALSE;
	sSYNetPeerBootstrapIsEnabled = TRUE;
	sSYNetPeerBootstrapMetadataApplied = FALSE;
	sSYNetPeerBootstrapPeerReady = FALSE;
	sSYNetPeerBootstrapStartReceived = FALSE;

	if (sSYNetPeerBootstrapIsHost != FALSE)
	{
		SCBattleState *state = &gSCManagerTransferBattleState;

		// SSB64_NETPLAY_LOBBY_TEST=1 stands in for the menus in unattended
		// tests: 2v2 teams, host + CPU Kirby vs joiner (Fox) + CPU Pikachu.
		if ((getenv("SSB64_NETPLAY_LOBBY_TEST") != NULL) && (atoi(getenv("SSB64_NETPLAY_LOBBY_TEST")) != 0))
		{
			static const s32 fkinds[4] = { nFTKindMario, nFTKindFox, nFTKindKirby, nFTKindPikachu };
			s32 p;

			*state = dSCManagerDefaultBattleState;
			state->game_type = nSCBattleGameTypeRoyal;
			state->game_rules = SCBATTLE_GAMERULE_STOCK;
			state->stocks = 1;
			state->is_team_battle = TRUE;
			state->is_team_attack = FALSE;
			state->time_limit = SCBATTLE_TIMELIMIT_INFINITE;
			state->pl_count = 1;
			state->cp_count = 3;
			gSCManagerSceneData.gkind = nGRKindCastle;

			for (p = 0; p < 4; p++)
			{
				state->players[p].pkind = (p == 0) ? nFTPlayerKindMan : nFTPlayerKindCom;
				state->players[p].fkind = fkinds[p];
				state->players[p].costume = 0;
				state->players[p].shade = 0;
				state->players[p].team = p % 2;
				state->players[p].handicap = 9;
				state->players[p].level = 3;
			}
		}

		// Player 2 is the online opponent: in the menus the host sets it to
		// CPU (any level) to pick its fighter; it becomes human here.
		if (state->players[1].pkind == nFTPlayerKindNot)
		{
			port_netplay_alert("To play online, set Player 2 to CPU (any level) on the character select "
			                   "screen: that slot becomes your online opponent. Playing this match offline.");
			sSYNetPeerIsEnabled = FALSE;
			return FALSE;
		}
		state->gkind = gSCManagerSceneData.gkind;
		menu_state = *state;
		syNetReplayCaptureBattleMetadata(state, &sSYNetPeerBootstrapMetadata);
		sSYNetPeerBootstrapMetadata.player_kinds[1] = nFTPlayerKindMan;
		{
			// A fresh seed per match (sent to the joiner, so both agree);
			// the menus' RNG state would repeat the same match every time.
			struct timespec ts;

			clock_gettime(CLOCK_REALTIME, &ts);
			sSYNetPeerBootstrapMetadata.rng_seed = (u32)ts.tv_sec ^ (u32)ts.tv_nsec;
		}
		sSYNetPeerLobbyHasMetadata = TRUE;
	}
	syNetPeerRunBootstrap();

	if ((sSYNetPeerIsActive != FALSE) &&
		((sSYNetPeerBootstrapIsHost != FALSE) ? (sSYNetPeerBootstrapPeerReady != FALSE) : (sSYNetPeerBootstrapStartReceived != FALSE)))
	{
		sSYNetPeerLobbyMatchOnline = TRUE;
		return FALSE;
	}
	// Nobody joined (host), the host never started (joiner), or the
	// handshake failed: play this match offline.
	syNetPeerCloseSocket();
	sSYNetPeerIsActive = FALSE;
	sSYNetPeerIsEnabled = FALSE;

	if (sSYNetPeerBootstrapIsHost == FALSE)
	{
		port_netplay_alert("Couldn't start an online match with the host. Open the game again to retry.");
		gSCManagerSceneData.scene_prev = gSCManagerSceneData.scene_curr;
		gSCManagerSceneData.scene_curr = nSCKindTitle;
		return TRUE;
	}
	gSCManagerTransferBattleState = menu_state;  // player 2 back to the CPU the host picked
	port_netplay_alert("Nobody joined the room, so this match is played offline (Player 2 is a CPU).");
	return FALSE;
}

// TRUE while the current VS battle is an online match.
sb32 syNetPeerLobbyCheckMatchOnline(void)
{
	return sSYNetPeerLobbyMatchOnline;
}

// After a host-set-up match: the joiner skips character select and waits
// for the host's next match instead.
s32 syNetPeerLobbyGetNextScene(s32 scene)
{
	if ((sSYNetPeerLobbyIsEnabled != FALSE) && (scene == nSCKindVSResults) &&
		(getenv("SSB64_NETPLAY_LOBBY_TEST") != NULL) && (atoi(getenv("SSB64_NETPLAY_LOBBY_TEST")) != 0))
	{
		return nSCKindVSBattle;  // unattended tests: nobody presses a button on the results screen
	}
	if ((sSYNetPeerLobbyIsEnabled != FALSE) && (scene == nSCKindPlayersVS) &&
		((sSYNetPeerBootstrapIsHost == FALSE) ||
		 ((getenv("SSB64_NETPLAY_LOBBY_TEST") != NULL) && (atoi(getenv("SSB64_NETPLAY_LOBBY_TEST")) != 0))))
	{
		return nSCKindVSBattle;  // (unattended tests: the host skips its menus too)
	}
	return scene;
}
#else
sb32 syNetPeerSessionCheckActive(void) { return FALSE; }
sb32 syNetPeerSessionCheckBorrowedSave(void) { return FALSE; }
u32 syNetPeerSessionNextRandom(void) { return 0; }
void syNetPeerSessionFuncRead(void) { }
sb32 syNetPeerLobbyBeginMatch(void) { return FALSE; }
sb32 syNetPeerLobbyCheckMatchOnline(void) { return FALSE; }
s32 syNetPeerLobbyGetNextScene(s32 scene) { return scene; }
#endif

void syNetPeerInitDebugEnv(void)
{
#ifdef PORT
	char *netplay_env = getenv("SSB64_NETPLAY");
	char *local_player_env;
	char *remote_player_env;
	char *delay_env;
	char *session_env;
	char *bind_env;
	char *peer_env;
	char *bootstrap_env;
	char *bootstrap_host_env;
	char *bootstrap_seed_env;

	sSYNetPeerIsEnabled = FALSE;
	sSYNetPeerIsConfigured = FALSE;
	sSYNetPeerDebugBotIsEnabled = FALSE;
	sSYNetPeerLockstepIsEnabled = TRUE;
	sSYNetPeerSimLossPercent = 0;
	sSYNetPeerSimLatencyUsecs = 0;
	sSYNetPeerSimJitterUsecs = 0;
	sSYNetPeerLocalPlayer = 0;
	sSYNetPeerRemotePlayer = 1;
	sSYNetPeerInputDelay = SYNETPEER_DEFAULT_INPUT_DELAY;
	sSYNetPeerSessionID = SYNETPEER_DEFAULT_SESSION_ID;
	sSYNetPeerBootstrapIsEnabled = FALSE;
	sSYNetPeerBootstrapIsHost = FALSE;
	sSYNetPeerBootstrapMetadataApplied = FALSE;
	sSYNetPeerBootstrapPeerReady = FALSE;
	sSYNetPeerBootstrapStartReceived = FALSE;
	sSYNetPeerBootstrapSeed = SYNETPEER_DEFAULT_BOOTSTRAP_SEED;
	sSYNetPeerBattleBarrierEnabled = FALSE;
	sSYNetPeerBattleLocalReady = FALSE;
	sSYNetPeerBattlePeerReady = FALSE;
	sSYNetPeerBattleStartSent = FALSE;
	sSYNetPeerBattleStartReceived = FALSE;
	sSYNetPeerBattleBarrierReleased = TRUE;
	sSYNetPeerBattleBarrierWaitFrames = 0;
	sSYNetPeerBattleStartRepeatFrames = 0;
	sSYNetPeerExecutionHoldFrames = 0;
	sSYNetPeerExecutionBeginLogged = FALSE;

	if ((netplay_env == NULL) || (atoi(netplay_env) == 0))
	{
		return;
	}
	sSYNetPeerIsEnabled = TRUE;

	local_player_env = getenv("SSB64_NETPLAY_LOCAL_PLAYER");
	remote_player_env = getenv("SSB64_NETPLAY_REMOTE_PLAYER");
	delay_env = getenv("SSB64_NETPLAY_DELAY");
	session_env = getenv("SSB64_NETPLAY_SESSION");
	bind_env = getenv("SSB64_NETPLAY_BIND");
	peer_env = getenv("SSB64_NETPLAY_PEER");
	bootstrap_env = getenv("SSB64_NETPLAY_BOOTSTRAP");
	bootstrap_host_env = getenv("SSB64_NETPLAY_HOST");
	bootstrap_seed_env = getenv("SSB64_NETPLAY_SEED");

#if !defined(_WIN32)
	// Room-code netplay: the server introduces the two players, so no
	// addresses are needed. The host plays P1 and the guest P2 unless the
	// player env vars say otherwise.
	sSYNetPeerUseRendezvous = (getenv("SSB64_NETPLAY_SERVER") != NULL) && (getenv("SSB64_NETPLAY_SERVER")[0] != '\0');

	if (sSYNetPeerUseRendezvous != FALSE)
	{
		sb32 is_host = (bootstrap_host_env != NULL) && (atoi(bootstrap_host_env) != 0);

		if (bind_env == NULL)
		{
			bind_env = "0.0.0.0:0";
		}
		peer_env = "0.0.0.0:0"; // filled in by the rendezvous
		if (bootstrap_env == NULL)
		{
			bootstrap_env = "1";
		}
		sSYNetPeerLocalPlayer = (is_host != FALSE) ? 0 : 1;
		sSYNetPeerRemotePlayer = (is_host != FALSE) ? 1 : 0;
	}
#endif
	if (local_player_env != NULL)
	{
		sSYNetPeerLocalPlayer = atoi(local_player_env);
	}
	if (remote_player_env != NULL)
	{
		sSYNetPeerRemotePlayer = atoi(remote_player_env);
	}
	if (delay_env != NULL)
	{
		s32 delay = atoi(delay_env);

		if (delay >= 0)
		{
			sSYNetPeerInputDelay = delay;
		}
	}
	if (session_env != NULL)
	{
		s32 session_id = atoi(session_env);

		if (session_id > 0)
		{
			sSYNetPeerSessionID = session_id;
		}
	}
	if ((bootstrap_env != NULL) && (atoi(bootstrap_env) != 0))
	{
		sSYNetPeerBootstrapIsEnabled = TRUE;
	}
	if ((bootstrap_host_env != NULL) && (atoi(bootstrap_host_env) != 0))
	{
		sSYNetPeerBootstrapIsHost = TRUE;
	}
	if (bootstrap_seed_env != NULL)
	{
		s32 seed = atoi(bootstrap_seed_env);

		if (seed > 0)
		{
			sSYNetPeerBootstrapSeed = seed;
		}
	}
	// SSB64_NETPLAY_BOT=1 drives the local player with scripted input so a
	// pair can be sync-tested in real gameplay without anyone at the keys.
	// SSB64_NETPLAY_BOT=2 just walks right, off the stage, every stock;
	// SSB64_NETPLAY_BOT=3 stands still (a punching bag for long tests).
	if ((getenv("SSB64_NETPLAY_BOT") != NULL) && (atoi(getenv("SSB64_NETPLAY_BOT")) != 0))
	{
		sSYNetPeerDebugBotIsEnabled = atoi(getenv("SSB64_NETPLAY_BOT"));
	}
	// SSB64_NETPLAY_ROLLBACK=1 predicts remote input and rolls back on a
	// misprediction (port/rollback) instead of waiting for it every tick;
	// SSB64_NETPLAY_ROLLBACK_WINDOW caps how far ahead of the peer we run.
	sSYNetPeerRollbackIsEnabled = FALSE;
	sSYNetPeerRollbackWindow = 8;
	if ((getenv("SSB64_NETPLAY_ROLLBACK") != NULL) && (atoi(getenv("SSB64_NETPLAY_ROLLBACK")) != 0))
	{
		sSYNetPeerRollbackIsEnabled = TRUE;
	}
	if (getenv("SSB64_NETPLAY_ROLLBACK_WINDOW") != NULL)
	{
		sSYNetPeerRollbackWindow = (u32)atoi(getenv("SSB64_NETPLAY_ROLLBACK_WINDOW"));
	}
	// SSB64_NETPLAY_LOCKSTEP=0 restores the old behavior of predicting late
	// remote input (which desyncs, as nothing ever corrects the guess).
	if ((getenv("SSB64_NETPLAY_LOCKSTEP") != NULL) && (atoi(getenv("SSB64_NETPLAY_LOCKSTEP")) == 0))
	{
		sSYNetPeerLockstepIsEnabled = FALSE;
	}
	// Simulated bad network for input packets: SIM_LOSS is a drop percentage,
	// SIM_LATENCY_MS a one-way delay and SIM_JITTER_MS a random extra delay.
	if (getenv("SSB64_NETPLAY_SIM_LOSS") != NULL)
	{
		sSYNetPeerSimLossPercent = atoi(getenv("SSB64_NETPLAY_SIM_LOSS"));
	}
	if (getenv("SSB64_NETPLAY_SIM_LATENCY_MS") != NULL)
	{
		sSYNetPeerSimLatencyUsecs = atoi(getenv("SSB64_NETPLAY_SIM_LATENCY_MS")) * 1000;
	}
	if (getenv("SSB64_NETPLAY_SIM_JITTER_MS") != NULL)
	{
		sSYNetPeerSimJitterUsecs = atoi(getenv("SSB64_NETPLAY_SIM_JITTER_MS")) * 1000;
	}
	if ((sSYNetPeerLocalPlayer < 0) || (sSYNetPeerLocalPlayer >= MAXCONTROLLERS) ||
		(sSYNetPeerRemotePlayer < 0) || (sSYNetPeerRemotePlayer >= MAXCONTROLLERS) ||
		(sSYNetPeerLocalPlayer == sSYNetPeerRemotePlayer))
	{
		port_log("SSB64 NetPeer: invalid players local=%d remote=%d\n",
		         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer);
		return;
	}
#if !defined(_WIN32)
	if ((syNetPeerParseIPv4Address(bind_env, &sSYNetPeerBindAddress) == FALSE) ||
		(syNetPeerParseIPv4Address(peer_env, &sSYNetPeerPeerAddress) == FALSE))
	{
		port_log("SSB64 NetPeer: invalid bind/peer; expected IPv4 host:port\n");
		return;
	}
	sSYNetPeerIsConfigured = TRUE;
	port_log("SSB64 NetPeer: configured local=%d remote=%d delay=%u session=%u bootstrap=%d host=%d seed=%u bind=%s peer=%s\n",
	         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer, sSYNetPeerInputDelay,
	         sSYNetPeerSessionID, sSYNetPeerBootstrapIsEnabled, sSYNetPeerBootstrapIsHost,
	         sSYNetPeerBootstrapSeed, bind_env, peer_env);

	sSYNetPeerSessionIsEnabled = (getenv("SSB64_NETPLAY_MODE") != NULL) &&
	                             (syNetPeerStringEquals(getenv("SSB64_NETPLAY_MODE"), "session") != FALSE) &&
	                             (sSYNetPeerUseRendezvous != FALSE);
	if (sSYNetPeerSessionIsEnabled != FALSE)
	{
		struct timespec ts;

		// Rollback only inside battles; the menus run in lockstep.
		sSYNetPeerSessionRollbackArmed = sSYNetPeerRollbackIsEnabled;
		sSYNetPeerRollbackIsEnabled = FALSE;
		sSYNetPeerBootstrapIsEnabled = TRUE;

		if (sSYNetPeerBootstrapIsHost != FALSE)
		{
			// The host's VS rules and a fresh seed (the joiner adopts both).
			// Players come from the defaults (they're picked in the menus).
			SYNetInputReplayMetadata rules;

			syNetReplayCaptureBattleMetadata(&gSCManagerTransferBattleState, &rules);
			syNetPeerMakeBootstrapMetadata(&sSYNetPeerBootstrapMetadata);
			sSYNetPeerBootstrapMetadata.stocks = rules.stocks;
			sSYNetPeerBootstrapMetadata.time_limit = rules.time_limit;
			sSYNetPeerBootstrapMetadata.item_switch = rules.item_switch;
			sSYNetPeerBootstrapMetadata.item_toggles = rules.item_toggles;
			sSYNetPeerBootstrapMetadata.game_rules = rules.game_rules;
			sSYNetPeerBootstrapMetadata.is_team_battle = rules.is_team_battle;
			sSYNetPeerBootstrapMetadata.handicap = rules.handicap;
			sSYNetPeerBootstrapMetadata.is_team_attack = rules.is_team_attack;
			sSYNetPeerBootstrapMetadata.damage_ratio = rules.damage_ratio;
			sSYNetPeerBootstrapMetadata.item_appearance_rate = rules.item_appearance_rate;
			clock_gettime(CLOCK_REALTIME, &ts);
			sSYNetPeerBootstrapMetadata.rng_seed = (u32)ts.tv_sec ^ (u32)ts.tv_nsec;
			sSYNetPeerLobbyHasMetadata = TRUE;
		}
		syNetPeerRunBootstrap();

		if ((sSYNetPeerIsActive != FALSE) &&
			((sSYNetPeerBootstrapIsHost != FALSE) ? (sSYNetPeerBootstrapPeerReady != FALSE) : (sSYNetPeerBootstrapStartReceived != FALSE)))
		{
			syNetPeerSessionBegin();
		}
		else
		{
			syNetPeerCloseSocket();
			sSYNetPeerIsActive = FALSE;
			sSYNetPeerIsEnabled = FALSE;
			port_netplay_alert("Couldn't start the online session. Playing offline.");
		}
		return;
	}

	sSYNetPeerLobbyIsEnabled = (getenv("SSB64_NETPLAY_LOBBY") != NULL) && (atoi(getenv("SSB64_NETPLAY_LOBBY")) != 0) &&
	                           (sSYNetPeerUseRendezvous != FALSE);
	if (sSYNetPeerLobbyIsEnabled != FALSE)
	{
		// No connection at boot: the host goes to the VS menus to set up the
		// match, the joiner straight to the battle scene, where
		// syNetPeerLobbyBeginMatch() connects and waits for the host.
		if ((sSYNetPeerBootstrapIsHost == FALSE) || (getenv("SSB64_START_SCENE") == NULL))
		{
			gSCManagerSceneData.scene_prev = nSCKindVSMode;
			gSCManagerSceneData.scene_curr = (sSYNetPeerBootstrapIsHost != FALSE) ? nSCKindVSMode : nSCKindVSBattle;
		}
		port_log("SSB64 NetPeer: host-set-up matches (%s)\n", (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "joiner");
		return;
	}
	syNetPeerRunBootstrap();
#else
	port_log("SSB64 NetPeer: debug UDP netplay is not implemented on Windows yet\n");
#endif
#endif
}

void syNetPeerStartVSSession(void)
{
	sSYNetPeerNextCheckpointTick = 0;
	memset(sSYNetPeerTickHashTick, 0xFF, sizeof(sSYNetPeerTickHashTick));
#if defined(PORT) && !defined(_WIN32)
	sSYNetPeerRemoteAdvantageValid = FALSE;
	sSYNetPeerTimeSyncSkips = 0;
	sSYNetPeerTimeSyncCooldown = 0;
	sSYNetPeerTimeSyncAhead16 = 0;
#endif

#if defined(PORT) && !defined(_WIN32)
	if ((sSYNetPeerIsEnabled == FALSE) || (sSYNetPeerIsConfigured == FALSE))
	{
		return;
	}
	if (sSYNetPeerSessionIsActive != FALSE)
	{
		// One continuous session: keep the connection, tick and slots; only
		// arm rollback (if configured) for the battle.
		sSYNetPeerRollbackIsEnabled = sSYNetPeerSessionRollbackArmed;
		sSYNetPeerNextCheckpointTick = syNetInputGetTick();
		port_log("SSB64 NetPeer: session battle start tick=%u rollback=%d\n", syNetInputGetTick(), sSYNetPeerRollbackIsEnabled);
		return;
	}
	if (syNetPeerOpenSocket() == FALSE)
	{
		return;
	}
	syNetPeerResetSessionCounters();
	syNetPeerSyncCheckReset();
	sSYNetPeerIsActive = TRUE;
	sSYNetPeerBattleBarrierEnabled = sSYNetPeerBootstrapIsEnabled;
	sSYNetPeerBattleLocalReady = sSYNetPeerBattleBarrierEnabled;
	sSYNetPeerBattlePeerReady = FALSE;
	sSYNetPeerBattleStartSent = FALSE;
	sSYNetPeerBattleStartReceived = FALSE;
	sSYNetPeerBattleBarrierReleased = (sSYNetPeerBattleBarrierEnabled == FALSE) ? TRUE : FALSE;
	sSYNetPeerBattleBarrierWaitFrames = 0;
	sSYNetPeerBattleStartRepeatFrames = 0;
	sSYNetPeerExecutionHoldFrames = 0;
	sSYNetPeerExecutionBeginLogged = (sSYNetPeerBattleBarrierEnabled == FALSE) ? TRUE : FALSE;

	syNetInputSetSlotSource(sSYNetPeerLocalPlayer, nSYNetInputSourceLocal);
	syNetInputSetLocalInputDelay(sSYNetPeerInputDelay);
	syNetInputSetSlotSource(sSYNetPeerRemotePlayer, nSYNetInputSourceRemotePredicted);

	port_log("SSB64 NetPeer: VS session start role=%s local=%d remote=%d delay=%u barrier=%d tick=%u\n",
	         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
	         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer, sSYNetPeerInputDelay,
	         sSYNetPeerBattleBarrierEnabled, syNetInputGetTick());
#endif
}

#if defined(PORT) && !defined(_WIN32)
// Per-connection statistics and sequence state (a VS session, or a whole
// online session).
void syNetPeerResetSessionCounters(void)
{
	sSYNetPeerHighestRemoteTick = 0;
	sSYNetPeerStallTicks = 0;
	sSYNetPeerStallUsecs = 0;
	sSYNetPeerStallTimeouts = 0;
	sSYNetPeerPacketsSent = 0;
	sSYNetPeerPacketsReceived = 0;
	sSYNetPeerPacketsDropped = 0;
	sSYNetPeerFramesStaged = 0;
	sSYNetPeerLateFrames = 0;
	sSYNetPeerInputChecksum = 2166136261U;
	sSYNetPeerLastLogTick = 0;
	sSYNetPeerSendSeq = 0;
	sSYNetPeerRecvSeqInitialized = FALSE;
	sSYNetPeerRecvSeqHighWater = 0;
	sSYNetPeerSeqGaps = 0;
	sSYNetPeerSeqDuplicates = 0;
	sSYNetPeerSeqOutOfOrder = 0;
	sSYNetPeerLastPeerAckTick = 0;
	sSYNetPeerLastPacketTicksValid = FALSE;
}
#endif

sb32 syNetPeerCheckBattleExecutionReady(void)
{
	if ((sSYNetPeerIsEnabled == FALSE) || (sSYNetPeerBootstrapIsEnabled == FALSE) ||
		(sSYNetPeerBattleBarrierEnabled == FALSE))
	{
		return TRUE;
	}
	return sSYNetPeerBattleBarrierReleased;
}

sb32 syNetPeerCheckStartBarrierReleased(void)
{
	return syNetPeerCheckBattleExecutionReady();
}

void syNetPeerBuildPacket(u8 *buffer, u32 *out_size)
{
	SYNetInputFrame published_frame;
	SYNetInputFrame history_frame;
	SYNetPeerPacketFrame frames[SYNETPEER_MAX_PACKET_FRAMES];
	SYNetPeerPacketFrame zero_frame;
	u8 *cursor = buffer;
	u32 latest_tick;
	u32 checksum;
	s32 frame_count = 0;
	s32 back;
	s32 i;

	memset(frames, 0, sizeof(frames));
	memset(&zero_frame, 0, sizeof(zero_frame));

	if (syNetInputGetPublishedFrame(sSYNetPeerLocalPlayer, &published_frame) == FALSE)
	{
		*out_size = 0;
		return;
	}
	// The newest local sample is tagged published tick + delay; send the last
	// 16 of those future-tagged samples as-is (the peer applies each one on
	// the same tick we do).
	latest_tick = published_frame.tick + syNetInputGetLocalInputDelay();

	for (back = SYNETPEER_MAX_PACKET_FRAMES - 1; back >= 0; back--)
	{
		if ((latest_tick >= (u32)back) &&
			(syNetInputGetDelayedLocalFrame(sSYNetPeerLocalPlayer, latest_tick - back, &history_frame) != FALSE))
		{
			frames[frame_count].tick = history_frame.tick;
			frames[frame_count].buttons = history_frame.buttons;
			frames[frame_count].stick_x = history_frame.stick_x;
			frames[frame_count].stick_y = history_frame.stick_y;
			frame_count++;
		}
	}
	checksum = syNetPeerChecksumPacket
	(
		sSYNetPeerSessionID,
		sSYNetPeerHighestRemoteTick,
		sSYNetPeerSendSeq,
		(u8)sSYNetPeerLocalPlayer,
		(u8)frame_count,
		frames
	);

	syNetPeerWriteU32(&cursor, SYNETPEER_MAGIC);
	syNetPeerWriteU16(&cursor, SYNETPEER_VERSION);
	syNetPeerWriteU16(&cursor, 0);
	syNetPeerWriteU32(&cursor, sSYNetPeerSessionID);
	syNetPeerWriteU32(&cursor, sSYNetPeerHighestRemoteTick);
	syNetPeerWriteU32(&cursor, sSYNetPeerSendSeq);
	syNetPeerWriteU8(&cursor, (u8)sSYNetPeerLocalPlayer);
	syNetPeerWriteU8(&cursor, (u8)frame_count);
	syNetPeerWriteU8(&cursor, (u8)sSYNetPeerLocalPlayer);
	syNetPeerWriteU8(&cursor, (u8)sSYNetPeerRemotePlayer);

	for (i = 0; i < SYNETPEER_MAX_PACKET_FRAMES; i++)
	{
		SYNetPeerPacketFrame *frame = (i < frame_count) ? &frames[i] : &zero_frame;

		syNetPeerWriteU32(&cursor, frame->tick);
		syNetPeerWriteU16(&cursor, frame->buttons);
		syNetPeerWriteU8(&cursor, (u8)frame->stick_x);
		syNetPeerWriteU8(&cursor, (u8)frame->stick_y);
	}
	syNetPeerWriteU32(&cursor, checksum);
	*out_size = SYNETPEER_PACKET_BYTES;
}

#if defined(PORT) && !defined(_WIN32)
typedef struct SYNetPeerSimPacket
{
	u64 release_usecs;
	u32 size;
	u8 data[SYNETPEER_PACKET_BYTES];

} SYNetPeerSimPacket;

SYNetPeerSimPacket sSYNetPeerSimQueue[SYNETPEER_SIM_QUEUE_LENGTH];
u32 sSYNetPeerSimQueueCount;

u64 syNetPeerSimNowUsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ((u64)ts.tv_sec * 1000000) + ((u64)ts.tv_nsec / 1000);
}

u32 syNetPeerSimNextRandom(void)
{
	// xorshift32; network simulation only, never gameplay state.
	if (sSYNetPeerSimRandom == 0)
	{
		sSYNetPeerSimRandom = 0x2545F491U ^ (u32)sSYNetPeerLocalPlayer;
	}
	sSYNetPeerSimRandom ^= sSYNetPeerSimRandom << 13;
	sSYNetPeerSimRandom ^= sSYNetPeerSimRandom >> 17;
	sSYNetPeerSimRandom ^= sSYNetPeerSimRandom << 5;

	return sSYNetPeerSimRandom;
}

void syNetPeerSimFlush(void)
{
	u64 now = syNetPeerSimNowUsecs();
	u32 i = 0;

	while (i < sSYNetPeerSimQueueCount)
	{
		if (sSYNetPeerSimQueue[i].release_usecs <= now)
		{
			syNetPeerSendBytes(sSYNetPeerSimQueue[i].data, sSYNetPeerSimQueue[i].size);
			sSYNetPeerSimQueue[i] = sSYNetPeerSimQueue[--sSYNetPeerSimQueueCount];
		}
		else i++;
	}
}

// Returns TRUE if the packet left (or was deliberately lost in) the simulator.
sb32 syNetPeerSimSend(const u8 *buffer, u32 size)
{
	SYNetPeerSimPacket *packet;

	if ((sSYNetPeerSimLossPercent == 0) && (sSYNetPeerSimLatencyUsecs == 0) && (sSYNetPeerSimJitterUsecs == 0))
	{
		return (sendto(sSYNetPeerSocket, buffer, size, 0, (struct sockaddr*)&sSYNetPeerPeerAddress,
		               sizeof(sSYNetPeerPeerAddress)) == (ssize_t)size) ? TRUE : FALSE;
	}
	syNetPeerSimFlush();

	if ((syNetPeerSimNextRandom() % 100) < sSYNetPeerSimLossPercent)
	{
		sSYNetPeerSimDropped++;
		return TRUE;
	}
	if ((sSYNetPeerSimQueueCount >= SYNETPEER_SIM_QUEUE_LENGTH) || (size > SYNETPEER_PACKET_BYTES))
	{
		sSYNetPeerSimDropped++;
		return TRUE;
	}
	packet = &sSYNetPeerSimQueue[sSYNetPeerSimQueueCount++];
	packet->release_usecs = syNetPeerSimNowUsecs() + sSYNetPeerSimLatencyUsecs +
		((sSYNetPeerSimJitterUsecs != 0) ? (syNetPeerSimNextRandom() % sSYNetPeerSimJitterUsecs) : 0);
	packet->size = size;
	memcpy(packet->data, buffer, size);
	syNetPeerSimFlush();

	return TRUE;
}
#endif

void syNetPeerSendLocalInput(void)
{
#if defined(PORT) && !defined(_WIN32)
	u8 buffer[SYNETPEER_PACKET_BYTES];
	u32 size;

	syNetPeerBuildPacket(buffer, &size);

	if (size == 0)
	{
		return;
	}
	if (syNetPeerSimSend(buffer, size) != FALSE)
	{
		sSYNetPeerPacketsSent++;
		sSYNetPeerSendSeq++;
	}
#endif
}

#if defined(PORT) && !defined(_WIN32)
// Round-trip probes: PING carries the sender's clock (usecs), PONG echoes it.
// Measurement only; nothing here affects gameplay.
u32 sSYNetPeerPingCountdown;
u32 sSYNetPeerRttWindowCount;
u32 sSYNetPeerRttWindowSumUsecs;
u32 sSYNetPeerRttWindowMaxUsecs;
u32 sSYNetPeerRttMaxUsecs;
u32 sSYNetPeerRttHistogram[5]; // <20, <50, <100, <150, >=150 ms
// Time sync: each side's "advantage" is its tick minus the newest remote
// tick it has. Half the difference between ours and the peer's is how many
// frames we run ahead of the peer; the side ahead slows down a little.
s32 sSYNetPeerRemoteAdvantage;
sb32 sSYNetPeerRemoteAdvantageValid;

s32 syNetPeerGetLocalAdvantage(void)
{
	return (s32)syNetInputGetTick() - (s32)sSYNetPeerHighestRemoteTick;
}

void syNetPeerSendTimingPacket(u16 packet_type, u32 stamp)
{
	u8 buffer[SYNETPEER_TIMING_PACKET_BYTES];
	u8 *cursor = buffer;
	u32 checksum;

	syNetPeerWriteU32(&cursor, SYNETPEER_MAGIC);
	syNetPeerWriteU16(&cursor, SYNETPEER_VERSION);
	syNetPeerWriteU16(&cursor, packet_type);
	syNetPeerWriteU32(&cursor, sSYNetPeerSessionID);
	syNetPeerWriteU32(&cursor, stamp);
	syNetPeerWriteU32(&cursor, (u32)syNetPeerGetLocalAdvantage());
	checksum = syNetPeerChecksumBytes(buffer, cursor - buffer);
	syNetPeerWriteU32(&cursor, checksum);
	syNetPeerSimSend(buffer, SYNETPEER_TIMING_PACKET_BYTES);
}

void syNetPeerHandleTimingPacket(const u8 *buffer, s32 size)
{
	const u8 *cursor = buffer;
	u32 magic, session_id, stamp, advantage, checksum, rtt;
	u16 version, packet_type;

	if (size != SYNETPEER_TIMING_PACKET_BYTES)
	{
		return;
	}
	magic = syNetPeerReadU32(&cursor);
	version = syNetPeerReadU16(&cursor);
	packet_type = syNetPeerReadU16(&cursor);
	session_id = syNetPeerReadU32(&cursor);
	stamp = syNetPeerReadU32(&cursor);
	advantage = syNetPeerReadU32(&cursor);
	checksum = syNetPeerReadU32(&cursor);

	if ((magic != SYNETPEER_MAGIC) || (version != SYNETPEER_VERSION) || (session_id != sSYNetPeerSessionID) ||
		(checksum != syNetPeerChecksumBytes(buffer, SYNETPEER_TIMING_PACKET_BYTES - 4)))
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	sSYNetPeerRemoteAdvantage = (s32)advantage;
	sSYNetPeerRemoteAdvantageValid = TRUE;

	if (packet_type == SYNETPEER_PACKET_PING)
	{
		syNetPeerSendTimingPacket(SYNETPEER_PACKET_PONG, stamp);
		return;
	}
	if (packet_type != SYNETPEER_PACKET_PONG)
	{
		return;
	}
	rtt = (u32)syNetPeerSimNowUsecs() - stamp;

	sSYNetPeerRttWindowCount++;
	sSYNetPeerRttWindowSumUsecs += rtt;
	if (rtt > sSYNetPeerRttWindowMaxUsecs)
	{
		sSYNetPeerRttWindowMaxUsecs = rtt;
	}
	if (rtt > sSYNetPeerRttMaxUsecs)
	{
		sSYNetPeerRttMaxUsecs = rtt;
	}
	sSYNetPeerRttHistogram[(rtt < 20000) ? 0 : (rtt < 50000) ? 1 : (rtt < 100000) ? 2 : (rtt < 150000) ? 3 : 4]++;
}

// Rollback time sync: when we run a frame or more ahead of the peer, skip a
// game step now and then (the port re-presents the last frame) so the peer
// catches up instead of us predicting, and rolling back, ever further ahead.
// Frame pacing is vsync-bound, so sleeping would not slow us down.
#define SYNETPEER_TIMESYNC_SKIP_SPACING 30 // frames between skips
#define SYNETPEER_TIMESYNC_THRESHOLD 3      // skip when 1.5+ frames ahead (in half frames)

u32 sSYNetPeerTimeSyncSkips;
u32 sSYNetPeerTimeSyncCooldown;
s32 sSYNetPeerTimeSyncAhead16; // smoothed twice-frames-ahead, x16

sb32 syNetPeerTakeTimeSyncSkip(void)
{
	s32 ahead2; // twice the frames we are ahead

	if ((sSYNetPeerIsActive == FALSE) || (sSYNetPeerRollbackIsEnabled == FALSE) ||
		(sSYNetPeerRemoteAdvantageValid == FALSE) || (syNetPeerCheckBattleExecutionReady() == FALSE))
	{
		return FALSE;
	}
	// Jitter makes both advantages noisy, and the peer's arrives 4 times a
	// second; average over ~16 frames so the two sides don't take turns
	// believing they are ahead.
	ahead2 = syNetPeerGetLocalAdvantage() - sSYNetPeerRemoteAdvantage;
	sSYNetPeerTimeSyncAhead16 += ahead2 - (sSYNetPeerTimeSyncAhead16 / 16);

	if (sSYNetPeerTimeSyncCooldown != 0)
	{
		sSYNetPeerTimeSyncCooldown--;
		return FALSE;
	}
	if (sSYNetPeerTimeSyncAhead16 < SYNETPEER_TIMESYNC_THRESHOLD * 16)
	{
		return FALSE;
	}
	sSYNetPeerTimeSyncCooldown = SYNETPEER_TIMESYNC_SKIP_SPACING;
	sSYNetPeerTimeSyncAhead16 -= 2 * 16; // a skip closes the gap by one frame
	sSYNetPeerTimeSyncSkips++;
	return TRUE;
}

void syNetPeerUpdatePing(void)
{
	if (sSYNetPeerPingCountdown == 0)
	{
		syNetPeerSendTimingPacket(SYNETPEER_PACKET_PING, (u32)syNetPeerSimNowUsecs());
		sSYNetPeerPingCountdown = SYNETPEER_PING_INTERVAL;
	}
	sSYNetPeerPingCountdown--;
}

void syNetPeerLogRtt(void)
{
	if (sSYNetPeerRttWindowCount != 0)
	{
		port_log("SSB64 NetPeer: rtt avg=%ums max=%ums n=%u adv=%d peer_adv=%d timesync_skips=%u\n",
		         sSYNetPeerRttWindowSumUsecs / sSYNetPeerRttWindowCount / 1000, sSYNetPeerRttWindowMaxUsecs / 1000,
		         sSYNetPeerRttWindowCount, syNetPeerGetLocalAdvantage(), sSYNetPeerRemoteAdvantage,
		         sSYNetPeerTimeSyncSkips);
	}
	sSYNetPeerRttWindowCount = sSYNetPeerRttWindowSumUsecs = sSYNetPeerRttWindowMaxUsecs = 0;
}
#else
sb32 syNetPeerTakeTimeSyncSkip(void)
{
	return FALSE;
}
#endif

#if defined(PORT) && !defined(_WIN32)
// kind: 0 = SessionSync (outside battles), 1 = battle fighter checkpoint.
static void syNetPeerSyncCheckCompare(u32 tick, u32 kind, u32 local_hash, u32 remote_hash)
{
	if (local_hash == remote_hash)
	{
		sSYNetPeerSyncChecksMatched++;
		return;
	}
	if (sSYNetPeerDesyncReported != FALSE)
	{
		return;
	}
	sSYNetPeerDesyncReported = TRUE;
	port_log("SSB64 NetPeer: DESYNC detected tick=%u kind=%s local=%08X remote=%08X (after %u matching checks)\n",
	         tick, (kind == 0) ? "session" : "battle", local_hash, remote_hash, sSYNetPeerSyncChecksMatched);
	port_netplay_alert("The two games have gone out of sync, so what you see may now differ from your "
	                   "friend's screen. This is a bug: please send both players' logs (Files > BattleShip > ssb64.log).");
}

// Forget all fingerprints (a new session or battle starts at tick 0 again).
void syNetPeerSyncCheckReset(void)
{
	s32 i;

	for (i = 0; i < SYNETPEER_SYNC_CHECK_RING; i++)
	{
		sSYNetPeerSyncLocalTick[i] = U32_MAX;
		sSYNetPeerSyncRemoteTick[i] = U32_MAX;
		sSYNetPeerSyncComparedTick[i] = U32_MAX;
	}
	sSYNetPeerSyncChecksMatched = 0;
	sSYNetPeerDesyncReported = FALSE;
}

// Compare once both machines' fingerprints for (tick, kind) are known.
static void syNetPeerSyncCheckTryCompare(u32 slot)
{
	if ((sSYNetPeerSyncLocalTick[slot] == U32_MAX) || (sSYNetPeerSyncLocalTick[slot] != sSYNetPeerSyncRemoteTick[slot]) ||
		(sSYNetPeerSyncLocalKind[slot] != sSYNetPeerSyncRemoteKind[slot]) ||
		(sSYNetPeerSyncComparedTick[slot] == sSYNetPeerSyncLocalTick[slot]))
	{
		return;
	}
	sSYNetPeerSyncComparedTick[slot] = sSYNetPeerSyncLocalTick[slot];
	syNetPeerSyncCheckCompare(sSYNetPeerSyncLocalTick[slot], sSYNetPeerSyncLocalKind[slot],
	                          sSYNetPeerSyncLocalHash[slot], sSYNetPeerSyncRemoteHash[slot]);
}

// Record this machine's fingerprint for a tick, send it to the peer, and
// compare once the peer's arrives (either order).
void syNetPeerSyncCheckRecord(u32 tick, u32 kind, u32 hash)
{
	u8 buffer[SYNETPEER_SYNC_CHECK_PACKET_BYTES];
	u8 *cursor = buffer;
	u32 slot = (tick / 120) % SYNETPEER_SYNC_CHECK_RING;
	s32 i;

	if (sSYNetPeerIsActive == FALSE)
	{
		return;
	}
	sSYNetPeerSyncLocalTick[slot] = tick;
	sSYNetPeerSyncLocalKind[slot] = kind;
	sSYNetPeerSyncLocalHash[slot] = hash;

	syNetPeerWriteU32(&cursor, SYNETPEER_MAGIC);
	syNetPeerWriteU16(&cursor, SYNETPEER_VERSION);
	syNetPeerWriteU16(&cursor, SYNETPEER_PACKET_SYNC_CHECK);
	syNetPeerWriteU32(&cursor, sSYNetPeerSessionID);
	syNetPeerWriteU32(&cursor, tick);
	syNetPeerWriteU32(&cursor, kind);
	syNetPeerWriteU32(&cursor, hash);
	syNetPeerWriteU32(&cursor, syNetPeerChecksumBytes(buffer, cursor - buffer));
	for (i = 0; i < 2; i++)  // twice: a lost check only delays detection
	{
		syNetPeerSendBytes(buffer, sizeof(buffer));
	}
	syNetPeerSyncCheckTryCompare(slot);
}

void syNetPeerHandleSyncCheckPacket(const u8 *buffer, s32 size)
{
	const u8 *cursor = buffer;
	const u8 *trailer = buffer + size - 4;
	u32 tick;
	u32 slot;

	if ((syNetPeerReadU32(&cursor) != SYNETPEER_MAGIC) || (syNetPeerReadU16(&cursor) != SYNETPEER_VERSION) ||
		(syNetPeerReadU16(&cursor) != SYNETPEER_PACKET_SYNC_CHECK) || (syNetPeerReadU32(&cursor) != sSYNetPeerSessionID) ||
		(syNetPeerChecksumBytes(buffer, size - 4) != syNetPeerReadU32(&trailer)))
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	tick = syNetPeerReadU32(&cursor);
	slot = (tick / 120) % SYNETPEER_SYNC_CHECK_RING;
	sSYNetPeerSyncRemoteTick[slot] = tick;
	sSYNetPeerSyncRemoteKind[slot] = syNetPeerReadU32(&cursor);
	sSYNetPeerSyncRemoteHash[slot] = syNetPeerReadU32(&cursor);
	syNetPeerSyncCheckTryCompare(slot);
}
#endif

void syNetPeerHandlePacket(const u8 *buffer, s32 size)
{
	const u8 *cursor = buffer;
	SYNetPeerPacketFrame frames[SYNETPEER_MAX_PACKET_FRAMES];
	u32 magic;
	u32 session_id;
	u32 ack_tick;
	u32 packet_seq;
	u32 checksum;
	u32 expected_checksum;
	u16 version;
	u8 player;
	u8 frame_count;
	u8 packet_local_player;
	u8 packet_remote_player;
	u32 current_tick = syNetInputGetTick();
	s32 i;

#if defined(PORT) && !defined(_WIN32)
	if (size == SYNETPEER_CONTROL_PACKET_BYTES)
	{
		syNetPeerHandleControlPacket(buffer, size);
		return;
	}
	if (size == SYNETPEER_TIMING_PACKET_BYTES)
	{
		syNetPeerHandleTimingPacket(buffer, size);
		return;
	}
	if (size == SYNETPEER_SYNC_CHECK_PACKET_BYTES)
	{
		syNetPeerHandleSyncCheckPacket(buffer, size);
		return;
	}
#endif
	if (size != SYNETPEER_PACKET_BYTES)
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	memset(frames, 0, sizeof(frames));

	magic = syNetPeerReadU32(&cursor);
	version = syNetPeerReadU16(&cursor);
	(void)syNetPeerReadU16(&cursor);
	session_id = syNetPeerReadU32(&cursor);
	ack_tick = syNetPeerReadU32(&cursor);
	packet_seq = syNetPeerReadU32(&cursor);
	player = syNetPeerReadU8(&cursor);
	frame_count = syNetPeerReadU8(&cursor);
	packet_local_player = syNetPeerReadU8(&cursor);
	packet_remote_player = syNetPeerReadU8(&cursor);

	if ((magic != SYNETPEER_MAGIC) || (version != SYNETPEER_VERSION) ||
		(session_id != sSYNetPeerSessionID) || (player != (u8)sSYNetPeerRemotePlayer) ||
		(packet_local_player != (u8)sSYNetPeerRemotePlayer) ||
		(packet_remote_player != (u8)sSYNetPeerLocalPlayer) ||
		(frame_count > SYNETPEER_MAX_PACKET_FRAMES))
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	for (i = 0; i < SYNETPEER_MAX_PACKET_FRAMES; i++)
	{
		frames[i].tick = syNetPeerReadU32(&cursor);
		frames[i].buttons = syNetPeerReadU16(&cursor);
		frames[i].stick_x = (s8)syNetPeerReadU8(&cursor);
		frames[i].stick_y = (s8)syNetPeerReadU8(&cursor);
	}
	checksum = syNetPeerReadU32(&cursor);
	expected_checksum = syNetPeerChecksumPacket(session_id, ack_tick, packet_seq, player, frame_count, frames);

	if (checksum != expected_checksum)
	{
		sSYNetPeerPacketsDropped++;
		return;
	}
	sSYNetPeerPacketsReceived++;

	if (sSYNetPeerRecvSeqInitialized == FALSE)
	{
		sSYNetPeerRecvSeqHighWater = packet_seq;
		sSYNetPeerRecvSeqInitialized = TRUE;
	}
	else
	{
		if (packet_seq > sSYNetPeerRecvSeqHighWater)
		{
			sSYNetPeerSeqGaps += packet_seq - sSYNetPeerRecvSeqHighWater - 1U;
			sSYNetPeerRecvSeqHighWater = packet_seq;
		}
		else if (packet_seq == sSYNetPeerRecvSeqHighWater)
		{
			sSYNetPeerSeqDuplicates++;
		}
		else
		{
			sSYNetPeerSeqOutOfOrder++;
		}
	}
	sSYNetPeerLastPeerAckTick = ack_tick;

	if (frame_count > 0)
	{
		u32 oldest_tick_bundle = frames[0].tick;
		u32 newest_tick_bundle = frames[0].tick;

		for (i = 1; i < frame_count; i++)
		{
			if (frames[i].tick < oldest_tick_bundle)
			{
				oldest_tick_bundle = frames[i].tick;
			}
			if (frames[i].tick > newest_tick_bundle)
			{
				newest_tick_bundle = frames[i].tick;
			}
		}
		sSYNetPeerLastPacketOldestTick = oldest_tick_bundle;
		sSYNetPeerLastPacketNewestTick = newest_tick_bundle;
		sSYNetPeerLastPacketTicksValid = TRUE;
	}
	else sSYNetPeerLastPacketTicksValid = FALSE;

	for (i = 0; i < frame_count; i++)
	{
		sb32 is_new_remote_tick = (frames[i].tick > sSYNetPeerHighestRemoteTick) ? TRUE : FALSE;

		if ((is_new_remote_tick != FALSE) && (frames[i].tick < current_tick))
		{
			sSYNetPeerLateFrames++;
		}
		if (is_new_remote_tick != FALSE)
		{
			sSYNetPeerHighestRemoteTick = frames[i].tick;
		}
		syNetInputSetRemoteInput
		(
			sSYNetPeerRemotePlayer,
			frames[i].tick,
			frames[i].buttons,
			frames[i].stick_x,
			frames[i].stick_y
		);
		sSYNetPeerFramesStaged++;
		sSYNetPeerInputChecksum = syNetPeerChecksumAccumulateU32(sSYNetPeerInputChecksum, sSYNetPeerRemotePlayer);
		sSYNetPeerInputChecksum = syNetPeerChecksumAccumulateFrame(sSYNetPeerInputChecksum, &frames[i]);
	}
}

void syNetPeerReceiveRemoteInput(void)
{
#if defined(PORT) && !defined(_WIN32)
	u8 buffer[SYNETPEER_PACKET_BYTES];

	syNetPeerSimFlush();

	while (TRUE)
	{
		ssize_t size = recvfrom(sSYNetPeerSocket, buffer, sizeof(buffer), 0, NULL, NULL);

		if (size < 0)
		{
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
			{
				sSYNetPeerPacketsDropped++;
			}
			break;
		}
		syNetPeerHandlePacket(buffer, (s32)size);
	}
#endif
}

#ifdef PORT
void syNetPeerLogNetSyncValidationWithHash(u32 tick, u32 fighter_hash);

void syNetPeerLogNetSyncValidation(u32 tick)
{
	syNetPeerLogNetSyncValidationWithHash(tick, syNetSyncHashBattleFighters());
}

void syNetPeerLogNetSyncValidationWithHash(u32 tick, u32 fighter_hash)
{
	u32 checksums[MAXCONTROLLERS];
	u32 inp_all = 0;
	u32 win_begin = 0;
	u32 win_length = tick;

	if ((sSYNetPeerIsActive == FALSE) || (syNetPeerCheckBattleExecutionReady() == FALSE))
	{
		return;
	}
	if (tick >= SYNETPEER_VALIDATION_INPUT_WINDOW)
	{
		win_begin = tick - SYNETPEER_VALIDATION_INPUT_WINDOW;
		win_length = SYNETPEER_VALIDATION_INPUT_WINDOW;
	}
	syNetInputGetHistoryInputValueChecksumWindow(win_begin, win_length, checksums, &inp_all);

	port_log(
		"SSB64 NetSync: role=%s lp=%d rp=%d tick=%u hist_win=[%u,%u) all=0x%08X p0=0x%08X p1=0x%08X p2=0x%08X p3=0x%08X figh=0x%08X snd_next=%u rcv_hw=%u gap=%u dup=%u ooo=%u puck=%u pko=%u pkn=%u sent=%u recv=%u dropped=%u stg=%u hr=%u late=%u inpchk=0x%08X pkt_valid=%d\n",
		(sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
		sSYNetPeerLocalPlayer,
		sSYNetPeerRemotePlayer,
		tick,
		win_begin,
		win_begin + win_length,
		inp_all,
		checksums[0],
		checksums[1],
		checksums[2],
		checksums[3],
		fighter_hash,
		sSYNetPeerSendSeq,
		sSYNetPeerRecvSeqHighWater,
		sSYNetPeerSeqGaps,
		sSYNetPeerSeqDuplicates,
		sSYNetPeerSeqOutOfOrder,
		sSYNetPeerLastPeerAckTick,
		(sSYNetPeerLastPacketTicksValid != FALSE) ? sSYNetPeerLastPacketOldestTick : (~(u32)0),
		(sSYNetPeerLastPacketTicksValid != FALSE) ? sSYNetPeerLastPacketNewestTick : (~(u32)0),
		sSYNetPeerPacketsSent,
		sSYNetPeerPacketsReceived,
		sSYNetPeerPacketsDropped,
		sSYNetPeerFramesStaged,
		sSYNetPeerHighestRemoteTick,
		sSYNetPeerLateFrames,
		sSYNetPeerInputChecksum,
		sSYNetPeerLastPacketTicksValid);
#if defined(PORT) && !defined(_WIN32)
	syNetPeerSyncCheckRecord(tick, 1, fighter_hash);
#endif
}
#endif

void syNetPeerLogStats(void)
{
#ifdef PORT
	u32 tick = syNetInputGetTick();

	if ((tick == 0) || ((tick - sSYNetPeerLastLogTick) < SYNETPEER_LOG_INTERVAL))
	{
		return;
	}
	sSYNetPeerLastLogTick = tick;
#ifndef _WIN32
	syNetPeerLogRtt();
#endif

	port_log("SSB64 NetPeer: role=%s local=%d remote=%d barrier=%d execution_ready=%d tick=%u sent=%u recv=%u dropped=%u staged=%u highest_remote=%u late=%u snd_next=%u rcv_hw=%u seq_gap=%u seq_dup=%u seq_ooo=%u peer_ack=%u inpchk=0x%08X stalls=%u stall_ms=%u\n",
	         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
	         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer,
	         sSYNetPeerBattleBarrierReleased, syNetPeerCheckBattleExecutionReady(), tick,
	         sSYNetPeerPacketsSent, sSYNetPeerPacketsReceived, sSYNetPeerPacketsDropped,
	         sSYNetPeerFramesStaged, sSYNetPeerHighestRemoteTick, sSYNetPeerLateFrames,
	         sSYNetPeerSendSeq, sSYNetPeerRecvSeqHighWater, sSYNetPeerSeqGaps,
	         sSYNetPeerSeqDuplicates, sSYNetPeerSeqOutOfOrder,
	         sSYNetPeerLastPeerAckTick,
	         sSYNetPeerInputChecksum, sSYNetPeerStallTicks, sSYNetPeerStallUsecs / 1000);

#if !defined(_WIN32)
	// Fighter checkpoints exist only in battles (sessions log SessionSync
	// fingerprints elsewhere).
	if ((sSYNetPeerSessionIsActive != FALSE) && (syNetPeerSessionCheckInBattle() == FALSE))
	{
		return;
	}
#endif
	if (sSYNetPeerRollbackIsEnabled == FALSE)
	{
		syNetPeerLogNetSyncValidation(tick);
	}
#endif
}

// Rollback mode: a checkpoint is logged once every input before it is
// confirmed, from the hash recorded when that tick was (re)simulated.
void syNetPeerLogConfirmedCheckpoints(void)
{
#if defined(PORT) && !defined(_WIN32)
	u32 tick = syNetInputGetTick();
	u32 slot;

	if (sSYNetPeerNextCheckpointTick == 0)
	{
		sSYNetPeerNextCheckpointTick = SYNETPEER_LOG_INTERVAL;
	}
	while ((sSYNetPeerNextCheckpointTick <= tick) && (sSYNetPeerHighestRemoteTick + 1 >= sSYNetPeerNextCheckpointTick) &&
	       (syNetInputCheckRollbackPendingBefore(sSYNetPeerNextCheckpointTick) == FALSE))
	{
		slot = sSYNetPeerNextCheckpointTick % SYNETPEER_TICK_HASH_RING;

		if (sSYNetPeerTickHashTick[slot] != sSYNetPeerNextCheckpointTick)
		{
			break; // this frame's hash is recorded after the frame; try next frame
		}
		syNetPeerLogNetSyncValidationWithHash(sSYNetPeerNextCheckpointTick, sSYNetPeerTickHash[slot]);
		sSYNetPeerNextCheckpointTick += SYNETPEER_LOG_INTERVAL;
	}
#endif
}

void syNetPeerLogExecutionHold(void)
{
#ifdef PORT
	if ((sSYNetPeerExecutionHoldFrames == 1) ||
		((sSYNetPeerExecutionHoldFrames % SYNETPEER_BARRIER_LOG_INTERVAL) == 0))
	{
		port_log("SSB64 NetPeer: execution hold role=%s local=%d remote=%d tick=%u hold=%u barrier_wait=%u peer_ready=%d start_sent=%d start_recv=%d highest_remote=%u late=%u\n",
		         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
		         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer, syNetInputGetTick(),
		         sSYNetPeerExecutionHoldFrames, sSYNetPeerBattleBarrierWaitFrames,
		         sSYNetPeerBattlePeerReady, sSYNetPeerBattleStartSent,
		         sSYNetPeerBattleStartReceived, sSYNetPeerHighestRemoteTick,
		         sSYNetPeerLateFrames);
	}
#endif
}

void syNetPeerLogExecutionBegin(void)
{
#ifdef PORT
	if (sSYNetPeerExecutionBeginLogged == FALSE)
	{
		sSYNetPeerExecutionBeginLogged = TRUE;
		port_log("SSB64 NetPeer: execution begin role=%s local=%d remote=%d tick=%u hold=%u barrier_wait=%u highest_remote=%u late=%u\n",
		         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
		         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer, syNetInputGetTick(),
		         sSYNetPeerExecutionHoldFrames, sSYNetPeerBattleBarrierWaitFrames,
		         sSYNetPeerHighestRemoteTick, sSYNetPeerLateFrames);
	}
#endif
}

void syNetPeerLogBarrierWait(void)
{
#ifdef PORT
	if ((sSYNetPeerBattleBarrierWaitFrames % SYNETPEER_BARRIER_LOG_INTERVAL) == 0)
	{
		port_log("SSB64 NetPeer: barrier wait role=%s local=%d remote=%d tick=%u local_ready=%d peer_ready=%d start_sent=%d start_recv=%d sent=%u recv=%u dropped=%u staged=%u highest_remote=%u late=%u\n",
		         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client",
		         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer, syNetInputGetTick(),
		         sSYNetPeerBattleLocalReady, sSYNetPeerBattlePeerReady,
		         sSYNetPeerBattleStartSent, sSYNetPeerBattleStartReceived, sSYNetPeerPacketsSent,
		         sSYNetPeerPacketsReceived, sSYNetPeerPacketsDropped,
		         sSYNetPeerFramesStaged, sSYNetPeerHighestRemoteTick, sSYNetPeerLateFrames);
	}
#endif
}

void syNetPeerReleaseBattleBarrier(const char *reason)
{
	if (sSYNetPeerBattleBarrierReleased == FALSE)
	{
		sSYNetPeerBattleBarrierReleased = TRUE;

#ifdef PORT
		port_log("SSB64 NetPeer: barrier release role=%s reason=%s local=%d remote=%d tick=%u wait=%u sent=%u recv=%u dropped=%u staged=%u highest_remote=%u late=%u\n",
		         (sSYNetPeerBootstrapIsHost != FALSE) ? "host" : "client", reason,
		         sSYNetPeerLocalPlayer, sSYNetPeerRemotePlayer, syNetInputGetTick(),
		         sSYNetPeerBattleBarrierWaitFrames, sSYNetPeerPacketsSent,
		         sSYNetPeerPacketsReceived, sSYNetPeerPacketsDropped,
		         sSYNetPeerFramesStaged, sSYNetPeerHighestRemoteTick, sSYNetPeerLateFrames);
#endif
	}
}

void syNetPeerUpdateStartBarrier(void)
{
#if defined(PORT) && !defined(_WIN32)
	if ((sSYNetPeerBattleBarrierEnabled == FALSE) || (sSYNetPeerBattleBarrierReleased != FALSE))
	{
		return;
	}
	sSYNetPeerBattleBarrierWaitFrames++;
	syNetPeerSendControlPacket(SYNETPEER_PACKET_BATTLE_READY);

	if (sSYNetPeerBattlePeerReady != FALSE)
	{
		if (sSYNetPeerBootstrapIsHost != FALSE)
		{
			syNetPeerSendControlPacket(SYNETPEER_PACKET_BATTLE_START);
			sSYNetPeerBattleStartSent = TRUE;

			if (sSYNetPeerBattleStartReceived != FALSE)
			{
				sSYNetPeerBattleStartRepeatFrames = SYNETPEER_BATTLE_START_REPEAT_FRAMES;
				syNetPeerReleaseBattleBarrier("client-ack");
			}
		}
		else if (sSYNetPeerBattleStartReceived != FALSE)
		{
			syNetPeerSendControlPacket(SYNETPEER_PACKET_BATTLE_START);
			sSYNetPeerBattleStartSent = TRUE;
			sSYNetPeerBattleStartRepeatFrames = SYNETPEER_BATTLE_START_REPEAT_FRAMES;
			syNetPeerReleaseBattleBarrier("host-start");
		}
	}
	syNetPeerLogBarrierWait();
#endif
}

void syNetPeerUpdateBattleGate(void)
{
	if (sSYNetPeerIsActive == FALSE)
	{
		return;
	}
	syNetPeerReceiveRemoteInput();
	syNetPeerUpdateStartBarrier();

	if (syNetPeerCheckBattleExecutionReady() == FALSE)
	{
		sSYNetPeerExecutionHoldFrames++;
		syNetPeerLogExecutionHold();
	}
	else syNetPeerLogExecutionBegin();
}

void syNetPeerUpdate(void)
{
	// A rollback resimulation replays ticks already sent and logged.
	if ((sSYNetPeerIsActive == FALSE) || (syNetInputCheckResimulating() != FALSE))
	{
		return;
	}
	syNetPeerUpdateBattleGate();

	if (syNetPeerCheckBattleExecutionReady() == FALSE)
	{
		return;
	}
	if (sSYNetPeerBattleStartRepeatFrames != 0)
	{
		syNetPeerSendControlPacket(SYNETPEER_PACKET_BATTLE_START);
		sSYNetPeerBattleStartRepeatFrames--;
	}
	syNetPeerSendLocalInput();
#if defined(PORT) && !defined(_WIN32)
	syNetPeerUpdatePing();
#endif
	syNetPeerLogStats();

	if (sSYNetPeerRollbackIsEnabled != FALSE)
	{
		syNetPeerLogConfirmedCheckpoints();
	}
}

// Online, the one local player is driven by this machine's first controller,
// whatever player slot the match assigned it.
sb32 syNetPeerCheckLocalPlayer(s32 player)
{
	return ((sSYNetPeerIsActive != FALSE) && (player == sSYNetPeerLocalPlayer)) ? TRUE : FALSE;
}

s32 syNetPeerGetControllerPort(s32 player)
{
	return (syNetPeerCheckLocalPlayer(player) != FALSE) ? 0 : player;
}

// Debug bot: deterministic pseudo-random input for the local netplay player,
// a pure function of (player, tick). Each choice is held for 12 ticks, with
// buttons pressed only for the first 3 so attacks re-trigger. Never START.
sb32 syNetPeerGetDebugBotInput(s32 player, u32 tick, u16 *buttons, s8 *stick_x, s8 *stick_y)
{
	static const s8 sticks[] = { -80, -40, 0, 0, 40, 80 };
	u32 h;

	if ((sSYNetPeerDebugBotIsEnabled == FALSE) || (sSYNetPeerIsActive == FALSE) ||
		(player != sSYNetPeerLocalPlayer))
	{
		return FALSE;
	}
	if (sSYNetPeerDebugBotIsEnabled == 3)
	{
		*stick_x = 0;
		*stick_y = 0;
		*buttons = 0;
		return TRUE;
	}
	if (sSYNetPeerDebugBotIsEnabled == 2)
	{
		*stick_x = 80;
		*stick_y = 0;
		*buttons = 0;
		return TRUE;
	}
	h = ((tick / 12) + 1) * 2654435761U;
	h ^= (u32)(player + 1) * 0x9E3779B9U;
	h ^= h >> 15;
	h *= 0x85EBCA6BU;
	h ^= h >> 13;

	*stick_x = sticks[h % 6];
	*stick_y = (((h >> 8) % 8) == 0) ? 80 : ((((h >> 8) % 8) == 1) ? -80 : 0);
	*buttons = 0;

	if ((tick % 12) < 3)
	{
		switch ((h >> 16) % 10)
		{
		case 0: case 1: case 2: *buttons = A_BUTTON; break;
		case 3: case 4: *buttons = B_BUTTON; break;
		case 5: *buttons = Z_TRIG; break;
		case 6: *buttons = U_CBUTTONS; break;
		default: break;
		}
	}
	return TRUE;
}

// Lockstep: block the game tick until the peer's input for it has arrived,
// so remote input is never guessed. Each side has already sent its input
// delay ticks ahead, so with delay >= 1 the two can never wait on each
// other. While waiting, resend our latest packet in case it was lost.
// Lockstep needs the peer's input for this tick; rollback only needs it
// within the window (older ticks are predicted and corrected later).
sb32 syNetPeerCheckRemoteInputReady(u32 tick)
{
	// The first ticks of a session are inside the input delay: neutral on
	// both machines by definition (and nothing has been sent yet).
	if ((sSYNetPeerSessionIsActive != FALSE) && (tick < sSYNetPeerInputDelay))
	{
		return TRUE;
	}
	if ((sSYNetPeerRollbackIsEnabled != FALSE) &&
		((sSYNetPeerSessionIsActive == FALSE) || (syNetPeerSessionCheckInBattle() != FALSE)))
	{
		return ((tick < sSYNetPeerRollbackWindow) || (sSYNetPeerHighestRemoteTick + sSYNetPeerRollbackWindow >= tick))
		           ? TRUE
		           : FALSE;
	}
	return syNetInputCheckRemoteFrame(sSYNetPeerRemotePlayer, tick);
}

// TRUE while a netplay battle or online session is running.
sb32 syNetPeerCheckActive(void)
{
	return sSYNetPeerIsActive;
}

sb32 syNetPeerCheckRollbackEnabled(void)
{
	return ((sSYNetPeerIsActive != FALSE) && (sSYNetPeerRollbackIsEnabled != FALSE)) ? TRUE : FALSE;
}

// Called by port/rollback after every simulated battle tick, resimulated
// ones included.
void syNetPeerRecordTickHash(void)
{
	u32 tick = syNetInputGetTick();

	sSYNetPeerTickHash[tick % SYNETPEER_TICK_HASH_RING] = syNetSyncHashBattleFighters();
	sSYNetPeerTickHashTick[tick % SYNETPEER_TICK_HASH_RING] = tick;
}

void syNetPeerWaitForRemoteInput(u32 tick)
{
#if defined(PORT) && !defined(_WIN32)
	u32 waited_usecs = 0;

	if ((sSYNetPeerIsActive == FALSE) || (sSYNetPeerLockstepIsEnabled == FALSE) ||
		(sSYNetPeerInputDelay == 0) || (syNetInputCheckResimulating() != FALSE))
	{
		return;
	}
	syNetPeerReceiveRemoteInput();

	if (syNetPeerCheckRemoteInputReady(tick) != FALSE)
	{
		return;
	}
	sSYNetPeerStallTicks++;

	{
	// In a session, outside battles, a long wait hands frames back to the
	// main loop (the app keeps answering the OS and can show a status) and
	// only gives up after 30 s; elsewhere the old 5 s timeout applies.
	const sb32 is_session_menu = (sSYNetPeerSessionIsActive != FALSE) && (syNetPeerSessionCheckInBattle() == FALSE);
	sb32 is_status_shown = FALSE;

	while (syNetPeerCheckRemoteInputReady(tick) == FALSE)
	{
		if (is_session_menu != FALSE)
		{
			if ((is_status_shown == FALSE) && (waited_usecs >= 1000000))
			{
				port_netplay_status("Online session", "Waiting for the other player...");
				is_status_shown = TRUE;
			}
			if (waited_usecs >= SYNETPEER_SESSION_LOCKSTEP_GIVEUP_USECS)
			{
				syNetPeerSessionEnd("the other player stopped responding");
				break;
			}
		}
		else if (waited_usecs >= SYNETPEER_LOCKSTEP_TIMEOUT_USECS)
		{
			sSYNetPeerStallTimeouts++;
			port_log("SSB64 NetPeer: lockstep timeout tick=%u highest_remote=%u; peer lost, predicting from now on\n",
			         tick, sSYNetPeerHighestRemoteTick);
			sSYNetPeerLockstepIsEnabled = FALSE;
			break;
		}
		if ((is_session_menu != FALSE) && (waited_usecs >= 100000))
		{
			syNetPeerSendLocalInput();
			port_netplay_boot_wait();  // one frame back to the main loop (~16 ms)
			waited_usecs += 16666;
		}
		else
		{
			if ((waited_usecs % SYNETPEER_LOCKSTEP_RESEND_USECS) == 0)
			{
				syNetPeerSendLocalInput();
			}
			usleep(SYNETPEER_LOCKSTEP_POLL_USECS);
			waited_usecs += SYNETPEER_LOCKSTEP_POLL_USECS;
			port_watchdog_note_yield();
		}
		syNetPeerReceiveRemoteInput();
	}
	if (is_status_shown != FALSE)
	{
		port_netplay_status(NULL, NULL);
	}
	}
	sSYNetPeerStallUsecs += waited_usecs;
#endif
}

void syNetPeerStopVSSession(void)
{
#if defined(PORT) && !defined(_WIN32)
	if (sSYNetPeerSessionIsActive != FALSE)
	{
		// Back to the menus: keep the session, lockstep again.
		sSYNetPeerRollbackIsEnabled = FALSE;
		port_log("SSB64 NetPeer: session battle stop tick=%u\n", syNetInputGetTick());
		return;
	}
	if (sSYNetPeerIsActive != FALSE)
	{
		port_log("SSB64 NetPeer: lockstep stalls=%u stall_ms=%u timeouts=%u sim_dropped=%u\n",
		         sSYNetPeerStallTicks, sSYNetPeerStallUsecs / 1000, sSYNetPeerStallTimeouts, sSYNetPeerSimDropped);
		port_log("SSB64 NetPeer: rtt histogram <20ms=%u <50ms=%u <100ms=%u <150ms=%u >=150ms=%u max=%ums\n",
		         sSYNetPeerRttHistogram[0], sSYNetPeerRttHistogram[1], sSYNetPeerRttHistogram[2],
		         sSYNetPeerRttHistogram[3], sSYNetPeerRttHistogram[4], sSYNetPeerRttMaxUsecs / 1000);
		port_log("SSB64 NetPeer: VS session stop sent=%u recv=%u dropped=%u staged=%u late=%u checksum=0x%08X\n",
		         sSYNetPeerPacketsSent, sSYNetPeerPacketsReceived, sSYNetPeerPacketsDropped,
		         sSYNetPeerFramesStaged, sSYNetPeerLateFrames, sSYNetPeerInputChecksum);
	}
	if ((sSYNetPeerLobbyIsEnabled != FALSE) && (sSYNetPeerBootstrapIsHost != FALSE) && (sSYNetPeerSocket >= 0))
	{
		// Close the room so the joiner waits for the next match.
		port_netplay_rendezvous_bye(sSYNetPeerSocket);
	}
	syNetPeerCloseSocket();
	if (sSYNetPeerLobbyIsEnabled != FALSE)
	{
		sSYNetPeerIsEnabled = TRUE;  // re-armed for the next match (an offline fallback cleared it)
	}
#endif
	sSYNetPeerIsActive = FALSE;
}
