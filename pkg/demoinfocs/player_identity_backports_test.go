package demoinfocs

import (
	"testing"

	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/common"
	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

func TestGetOrCreatePlayerRefreshesUserID(t *testing.T) {
	p := eventBackportParser(t)
	first := &common.PlayerInfo{UserID: 7, Name: "player", XUID: 76561198000000001}
	created, player := p.getOrCreatePlayer(10, first)
	if !created || player.UserID != 7 {
		t.Fatal("initial player identity not stored")
	}

	updated := &common.PlayerInfo{UserID: 9, Name: first.Name, XUID: first.XUID}
	created, same := p.getOrCreatePlayer(10, updated)
	if created || same != player || player.UserID != 9 || p.gameState.playersByUserID[9] != player {
		t.Fatal("existing player did not receive the updated user ID")
	}
	if p.gameState.playersByUserID[7] != nil {
		t.Fatal("old user ID still resolves to the player")
	}

	p.getOrCreatePlayer(10, nil)
	if player.UserID != 9 || p.gameState.playersByUserID[9] != player {
		t.Fatal("missing player info erased a known user ID")
	}
}

type controllerCleanupEntity struct {
	st.Entity
	id        int
	onDestroy func()
}

func (e *controllerCleanupEntity) ID() int { return e.id }
func (e *controllerCleanupEntity) Property(string) st.Property {
	return noUpdateProperty{}
}
func (e *controllerCleanupEntity) PropertyValueMust(string) st.PropertyValue {
	return st.PropertyValue{Any: "123", S2: true}
}
func (e *controllerCleanupEntity) PropertyValue(string) (st.PropertyValue, bool) {
	return st.PropertyValue{}, false
}
func (e *controllerCleanupEntity) OnDestroy(fn func()) { e.onDestroy = fn }

func TestControllerDestroyCleansOnlyItsOwnReferences(t *testing.T) {
	p := eventBackportParser(t)
	const entityID = 10
	p.rawPlayers[entityID-1] = &common.PlayerInfo{UserID: 7, Name: "old"}
	controller := &controllerCleanupEntity{id: entityID}
	p.bindNewPlayerControllerS2(controller)
	old := p.gameState.playersByEntityID[entityID]
	if controller.onDestroy == nil || p.gameState.playersByUserID[7] != old || p.gameState.playerControllerEntities[entityID] != controller {
		t.Fatal("controller was not indexed or destruction handler was not bound")
	}

	replacement := &common.Player{UserID: 7}
	newController := &controllerCleanupEntity{id: entityID}
	p.gameState.playersByEntityID[entityID] = replacement
	p.gameState.playersByUserID[7] = replacement
	p.gameState.playerControllerEntities[entityID] = newController
	controller.onDestroy()
	if p.gameState.playersByEntityID[entityID] != replacement || p.gameState.playersByUserID[7] != replacement || p.gameState.playerControllerEntities[entityID] != newController {
		t.Fatal("destroyed controller removed the replacement player's references")
	}

	old.Entity = newController
	old.IsConnected = true
	p.gameState.playersByEntityID[entityID] = old
	p.gameState.playersByUserID[7] = old
	controller.onDestroy()
	if !old.IsConnected || p.gameState.playersByEntityID[entityID] != old || p.gameState.playersByUserID[7] != old || p.gameState.playerControllerEntities[entityID] != newController {
		t.Fatal("old controller disconnected a player already attached to a new controller")
	}

	old.Entity = controller
	p.gameState.playersByEntityID[entityID] = old
	p.gameState.playersByUserID[7] = old
	p.gameState.playerControllerEntities[entityID] = controller
	controller.onDestroy()
	if p.gameState.playersByEntityID[entityID] != nil || p.gameState.playersByUserID[7] != nil || p.gameState.playerControllerEntities[entityID] != nil {
		t.Fatal("destroyed controller left stale player references")
	}
}
