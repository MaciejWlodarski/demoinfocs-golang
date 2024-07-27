package demoinfocs

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/markus-wa/go-unassert"
	"github.com/markus-wa/ice-cipher-go/pkg/ice"
	"google.golang.org/protobuf/proto"

	bit "github.com/markus-wa/demoinfocs-golang/v4/internal/bitread"
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

func (p *parser) handleEncryptedData(msg *msg.CSVCMsg_EncryptedData) {
	if msg.GetKeyType() != 2 {
		return
	}

	if p.decryptionKey == nil {
		p.msgDispatcher.Dispatch(events.ParserWarn{
			Type:    events.WarnTypeMissingNetMessageDecryptionKey,
			Message: "received encrypted net-message but no decryption key is set",
		})

		return
	}

	k := ice.NewKey(2, p.decryptionKey)
	b := k.DecryptAll(msg.Encrypted)

	r := bytes.NewReader(b)
	br := bit.NewSmallBitReader(r)

	const (
		byteLenPadding = 1
		byteLenWritten = 4
	)

	paddingBytes := br.ReadSingleByte()

	if int(paddingBytes) >= len(b)-byteLenPadding-byteLenWritten {
		p.eventDispatcher.Dispatch(events.ParserWarn{
			Message: "encrypted net-message has invalid number of padding bytes",
			Type:    events.WarnTypeCantReadEncryptedNetMessage,
		})

		return
	}

	br.Skip(int(paddingBytes) << 3)

	bBytesWritten := br.ReadBytes(4)
	nBytesWritten := int(binary.BigEndian.Uint32(bBytesWritten))

	if len(b) != byteLenPadding+byteLenWritten+int(paddingBytes)+nBytesWritten {
		p.eventDispatcher.Dispatch(events.ParserWarn{
			Message: "encrypted net-message has invalid length",
			Type:    events.WarnTypeCantReadEncryptedNetMessage,
		})

		return
	}

	cmd := br.ReadVarInt32()
	size := br.ReadVarInt32()

	m := p.netMessageForCmd(int(cmd))

	if m == nil {
		err := br.Pool()
		if err != nil {
			p.setError(err)
		}

		return
	}

	msgB := br.ReadBytes(int(size))

	err := proto.Unmarshal(msgB, m)
	if err != nil {
		p.setError(err)

		return
	}

	p.msgDispatcher.Dispatch(m)
}
