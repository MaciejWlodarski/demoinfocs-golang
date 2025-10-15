package demoinfocs

import (
	"fmt"

	"github.com/markus-wa/go-unassert"

	events "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/events"
	msg "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/msg"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/msgs2"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

func (p *parser) onEntity(e sendtables.Entity, op sendtables.EntityOp) error {
	if op&sendtables.EntityOpCreated > 0 {
		p.gameState.entities[e.ID()] = e
	} else if op&sendtables.EntityOpDeleted > 0 {
		if player, ok := p.gameState.Participants().AllByUserID()[e.ID()-1]; ok {
			player.Entity = nil
		}
		delete(p.gameState.entities, e.ID())
	}

	return nil
}

func (p *parser) handleSetConVar(setConVar *msg.CNETMsg_SetConVar) {
	updated := make(map[string]string)
	for _, cvar := range setConVar.Convars.Cvars {
		updated[cvar.GetName()] = cvar.GetValue()
		p.gameState.rules.conVars[cvar.GetName()] = cvar.GetValue()
	}

	p.eventDispatcher.Dispatch(events.ConVarsUpdated{
		UpdatedConVars: updated,
	})
}

func (p *parser) handleSetConVarS2(setConVar *msgs2.CNETMsg_SetConVar) {
	updated := make(map[string]string)
	for _, cvar := range setConVar.Convars.Cvars {
		updated[cvar.GetName()] = cvar.GetValue()
		p.gameState.rules.conVars[cvar.GetName()] = cvar.GetValue()
	}

	p.eventDispatcher.Dispatch(events.ConVarsUpdated{
		UpdatedConVars: updated,
	})
}

func (p *parser) handleServerInfo(srvInfo *msg.CSVCMsg_ServerInfo) {
	// srvInfo.MapCrc might be interesting as well
	p.tickInterval = srvInfo.GetTickInterval()

	p.eventDispatcher.Dispatch(events.TickRateInfoAvailable{
		TickRate: p.TickRate(),
		TickTime: p.TickTime(),
	})
}

// FIXME: combine with above
func (p *parser) handleServerInfoS2(srvInfo *msgs2.CSVCMsg_ServerInfo) {
	// srvInfo.MapCrc might be interesting as well
	p.tickInterval = srvInfo.GetTickInterval()

	p.eventDispatcher.Dispatch(events.TickRateInfoAvailable{
		TickRate: p.TickRate(),
		TickTime: p.TickTime(),
	})
}

func (p *parser) handleMessageSayText(msg *msgs2.CUserMessageSayText) {
	p.eventDispatcher.Dispatch(events.SayText{
		EntIdx:    int(msg.GetPlayerindex()),
		IsChat:    msg.GetChat(),
		IsChatAll: false,
		Text:      msg.GetText(),
	})
}

func (p *parser) handleMessageSayText2(msg *msgs2.CUserMessageSayText2) {
	p.eventDispatcher.Dispatch(events.SayText2{
		EntIdx:    int(msg.GetEntityindex()),
		IsChat:    msg.GetChat(),
		IsChatAll: false,
		MsgName:   msg.GetMessagename(),
		Params:    []string{msg.GetParam1(), msg.GetParam2(), msg.GetParam3(), msg.GetParam4()},
	})

	switch msg.GetMessagename() {
	case "Cstrike_Chat_All", "Cstrike_Chat_AllSpec":
		fallthrough
	case "Cstrike_Chat_AllDead":
		sender := p.gameState.playersByEntityID[int(msg.GetEntityindex())]

		p.eventDispatcher.Dispatch(events.ChatMessage{
			Sender:    sender,
			Text:      msg.GetParam2(),
			IsChatAll: false,
		})

	case "#CSGO_Coach_Join_T": // Ignore these
	case "#CSGO_Coach_Join_CT":
	case "#Cstrike_Name_Change":
	case "Cstrike_Chat_T_Loc":
	case "Cstrike_Chat_CT_Loc":
	case "Cstrike_Chat_T_Dead":
	case "Cstrike_Chat_CT_Dead":

	default:
		errMsg := fmt.Sprintf("skipped sending ChatMessageEvent for SayText2 with unknown MsgName %q", msg.GetMessagename())

		p.eventDispatcher.Dispatch(events.ParserWarn{Message: errMsg})
		unassert.Error(errMsg)
	}
}

func (p *parser) handleServerRankUpdate(msg *msgs2.CCSUsrMsg_ServerRankUpdate) {
	for _, v := range msg.RankUpdate {
		steamID32 := uint32(v.GetAccountId())
		player, ok := p.gameState.playersBySteamID32[steamID32]
		if !ok {
			errMsg := fmt.Sprintf("rank update for unknown player with SteamID32=%d", steamID32)

			p.eventDispatcher.Dispatch(events.ParserWarn{Message: errMsg})
			unassert.Error(errMsg)
		}

		p.eventDispatcher.Dispatch(events.RankUpdate{
			SteamID32:  v.GetAccountId(),
			RankOld:    int(v.GetRankOld()),
			RankNew:    int(v.GetRankNew()),
			WinCount:   int(v.GetNumWins()),
			RankChange: v.GetRankChange(),
			Player:     player,
		})
	}
}
