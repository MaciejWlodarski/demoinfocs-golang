package demoinfocs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/common"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/events"
)

// Validate flash attribution against actual projectile destruction events,
// separately from aggregate hashes, and preserve evidence for the new fallback.
func TestGOTVEventBackports(t *testing.T) {
	dir := os.Getenv("DEMOINFOCS_GOTV_DIR")
	if testing.Short() || dir == "" {
		t.Skip("requires local GOTV fixtures")
	}
	for _, name := range []string{"demo1", "demo2"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open(filepath.Join(dir, name+".dem"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			p := NewParser(file).(*parser)
			defer p.Close()
			explosions := map[int]events.FlashExplode{}
			flashes := 0
			sourceOwners := map[int]uint64{}
			sourceOwnerTicks := map[int]int{}
			verifiedFallback := false
			p.RegisterEventHandler(func(e events.FlashExplode) { explosions[e.GrenadeEntityID] = e })
			p.RegisterEventHandler(func(e events.FakePlayerFlashed) {
				explosion, ok := explosions[e.Projectile.Entity.ID()]
				if !ok || explosion.Thrower != e.Attacker {
					t.Errorf("tick %d: flash victim attributed to a projectile that did not explode in this frame", p.gameState.ingameTick)
				}
				flashes++
			})
			p.RegisterEventHandler(func(events.FrameDone) { clear(explosions) })
			p.RegisterEventHandler(func(e events.ItemNewOwner) {
				if e.Item != nil && e.Owner != nil && e.Item.Type == common.EqSmoke {
					sourceOwners[e.Item.EntityId] = e.Owner.SteamID64
					sourceOwnerTicks[e.Item.EntityId] = p.gameState.ingameTick
				}
			})
			p.RegisterEventHandler(func(e events.GrenadeProjectileThrow) {
				if name != "demo1" || p.gameState.ingameTick != 237119 || e.Projectile.Entity.ID() != 522 {
					return
				}
				w := e.Projectile.WeaponInstance
				if w.Entity == nil || e.Projectile.Thrower == nil || w.Owner != e.Projectile.Thrower {
					t.Error("fallback failed to preserve entity/thrower")
					return
				}
				remembered := p.gameState.lastKnownGrenadeWeapons[e.Projectile.Thrower][common.EqSmoke]
				if remembered == nil || remembered.Entity != w.Entity {
					t.Error("fallback does not refer to last-known smoke entity")
					return
				}
				if sourceOwners[w.EntityId] != e.Projectile.Thrower.SteamID64 {
					t.Error("no matching prior ownership event for recovered smoke entity")
				}
				if value, exists := w.Entity.PropertyValue("m_flThrowStrength"); !exists || value.Float() != 1 {
					t.Error("throw strength is not supported by entity data")
				}
				t.Logf("tick=237119 projectile=%d recovered weapon=%d owner=%d prior ownership tick=%d network throw_strength=%g", e.Projectile.Entity.ID(), w.EntityId, w.Owner.SteamID64, sourceOwnerTicks[w.EntityId], w.ThrowStrength())
				verifiedFallback = true
			})
			if err := p.ParseToEnd(); err != nil {
				t.Fatal(err)
			}
			if flashes == 0 {
				t.Fatal("no flash events exercised")
			}
			if name == "demo1" && !verifiedFallback {
				t.Fatal("expected grenade fallback case not exercised")
			}
			t.Logf("%d flash events matched actual same-frame detonations", flashes)
		})
	}
}
