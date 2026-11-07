#ifndef _SYNETPEER_H_
#define _SYNETPEER_H_

#include <PR/ultratypes.h>
#include <ssb_types.h>

extern void syNetPeerInitDebugEnv(void);
extern void syNetPeerStartVSSession(void);
extern sb32 syNetPeerCheckBattleExecutionReady(void);
extern sb32 syNetPeerCheckStartBarrierReleased(void);
extern void syNetPeerUpdateBattleGate(void);
extern void syNetPeerUpdate(void);
extern void syNetPeerStopVSSession(void);
extern void syNetPeerWaitForRemoteInput(u32 tick);
extern sb32 syNetPeerCheckLocalPlayer(s32 player);
extern sb32 syNetPeerCheckRollbackEnabled(void);
extern sb32 syNetPeerCheckRemoteInputReady(u32 tick);
extern void syNetPeerRecordTickHash(void);
extern sb32 syNetPeerTakeTimeSyncSkip(void);
extern s32 syNetPeerGetControllerPort(s32 player);
extern sb32 syNetPeerGetDebugBotInput(s32 player, u32 tick, u16 *buttons, s8 *stick_x, s8 *stick_y);

#endif /* _SYNETPEER_H_ */
