package demoinfocs_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	dem "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/common"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/events"
	msg "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/msgs2"
)

type gotvSnapshot struct {
	DemoSHA256                        string
	Map                               string
	Protocol                          int32
	HLTV                              bool
	Frames, LastTick, ScoreT, ScoreCT int
	Events                            map[string]int
	Warnings                          map[string]int
	Digests                           map[string]string
}

// The fixtures are supplied locally, never downloaded by the test. Missing
// fixtures skip the test unless the user explicitly configured their directory.
func TestGOTVCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("full GOTV regression; omit -short")
	}
	dir := os.Getenv("DEMOINFOCS_GOTV_DIR")
	if dir == "" {
		t.Skip("set DEMOINFOCS_GOTV_DIR to the local demo corpus")
	}
	for _, name := range []string{"demo1", "demo2"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open(filepath.Join(dir, name+".dem"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			fingerprint := sha256.New()
			if _, err := io.Copy(fingerprint, file); err != nil {
				t.Fatal(err)
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", "gotv", name+".json")
			var want gotvSnapshot
			update := os.Getenv("DEMOINFOCS_UPDATE_GOTV") == "1"
			if !update {
				data, err := os.ReadFile(golden)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &want); err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(fingerprint.Sum(nil)) != want.DemoSHA256 {
					t.Fatal("fixture SHA-256 differs; do not compare unrelated demos")
				}
			}
			got := collectGOTV(t, file)
			got.DemoSHA256 = hex.EncodeToString(fingerprint.Sum(nil))
			data, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
			if update {
				if err := os.WriteFile(golden, data, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !reflect.DeepEqual(got, want) {
				actual := filepath.Join(t.TempDir(), name+".actual.json")
				if err := os.WriteFile(actual, data, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Errorf("GOTV contract changed; expected %s; actual:\n%s", golden, data)
			}
		})
	}
}

func collectGOTV(t *testing.T, file *os.File) gotvSnapshot {
	t.Helper()
	result := gotvSnapshot{Events: map[string]int{}, Warnings: map[string]int{}, Digests: map[string]string{}}
	p := dem.NewParser(file)
	defer p.Close()
	hashes := map[string]hash.Hash{}
	pending := map[string][]string{}
	record := func(name string, data any) {
		// Copy the payload now; event players/equipment keep changing after callbacks.
		encoded, err := json.Marshal([]any{p.GameState().IngameTick(), data})
		if err != nil {
			panic(err)
		}
		pending[name] = append(pending[name], string(encoded))
	}
	flush := func() {
		for name, rows := range pending {
			// Creation handlers and map-backed collections can reorder independent
			// updates in the same frame. Preserve ticks/payloads/multiplicity, not that order.
			sort.Strings(rows)
			h := hashes[name]
			if h == nil {
				h = sha256.New()
				hashes[name] = h
			}
			for _, row := range rows {
				fmt.Fprintln(h, row)
			}
			pending[name] = rows[:0]
		}
	}
	p.RegisterNetMessageHandler(func(m *msg.CSVCMsg_ServerInfo) {
		result.Map = m.GetMapName()
		result.Protocol = m.GetProtocol()
		result.HLTV = m.GetIsHltv()
	})
	bootstrapSpawns := 0
	p.RegisterEventHandler(func(e any) {
		// The unmodified fork can emit one extra spawn during tick-zero entity
		// initialization, depending on map iteration order. Track it separately;
		// every spawn after bootstrap remains part of the strict contract.
		if _, spawn := e.(events.PlayerSpawn); spawn && p.GameState().IngameTick() == 0 {
			bootstrapSpawns++
			return
		}
		name := reflect.TypeOf(e).Name()
		result.Events[name]++
		switch e := e.(type) {
		case events.ParserWarn:
			result.Warnings[fmt.Sprint(e.Type)+":"+e.Message]++
		case events.Kill:
			record(name, []any{gotvPlayer(e.Killer), gotvPlayer(e.Victim), gotvPlayer(e.Assister), gotvWeapon(e.Weapon), e.IsHeadshot, e.InAir})
		case events.PlayerHurt:
			record(name, []any{gotvPlayer(e.Attacker), gotvPlayer(e.Player), gotvWeapon(e.Weapon), e.Health, e.Armor, e.HealthDamage, e.ArmorDamage, e.HitGroup})
		case events.WeaponFire:
			record(name, []any{gotvPlayer(e.Shooter), gotvWeapon(e.Weapon)})
		case events.GrenadeProjectileThrow:
			record(name, []any{gotvPlayer(e.Projectile.Thrower), gotvWeapon(e.Projectile.WeaponInstance), e.Projectile.Position()})
		case events.RoundEnd:
			record(name, []any{e.Winner, e.Reason})
		// The 17 fork-only event types consumed by demo-parser-cs2.
		case events.FakeSmokeStart:
			record(name, []any{gotvPlayer(e.Thrower), e.GrenadeEntityID, e.Position})
		case events.InfernoFireStart:
			record(name, []any{e.Inferno.Entity.ID(), e.Index, e.Fire})
		case events.FakePlayerFlashed:
			record(name, []any{gotvPlayer(e.Player), gotvPlayer(e.Attacker), e.Duration})
		case events.PlayerSpawn:
			record(name, gotvPlayer(e.Player))
		case events.HandSwitch:
			record(name, []any{gotvPlayer(e.Player), e.Left})
		case events.Timeout:
			record(name, []any{e.TeamState.Team(), e.Tech})
		case events.ItemStateUpdate:
			record(name, []any{gotvPlayer(e.Owner), gotvWeapon(e.Item), e.State})
		case events.ItemNewOwner:
			record(name, []any{gotvPlayer(e.Owner), gotvWeapon(e.Item)})
		case events.ItemDroped:
			record(name, []any{gotvPlayer(e.Owner), gotvWeapon(e.Item)})
		case events.DefuseKitUpdate:
			record(name, []any{gotvPlayer(e.Player), e.HasKit})
		case events.BombOwnerUpdate:
			record(name, []any{gotvPlayer(e.NewOwner), gotvPlayer(e.PrevOwner)})
		case events.ArmorUpdate:
			record(name, []any{gotvPlayer(e.Player), e.Armor})
		case events.HelmetUpdate:
			record(name, []any{gotvPlayer(e.Player), e.HasHelmet})
		case events.GrenadeUpdate:
			record(name, []any{gotvPlayer(e.Player), e.Type, e.Quantity})
		case events.KillsUpdate:
			record(name, []any{gotvPlayer(e.Player), e.Kills})
		case events.DeathsUpdate:
			record(name, []any{gotvPlayer(e.Player), e.Deaths})
		case events.MoneyUpdate:
			record(name, []any{gotvPlayer(e.Player), e.Money})
		}
	})
	lastSample := -999999
	p.RegisterEventHandler(func(events.FrameDone) {
		tick := p.GameState().IngameTick()
		if tick >= lastSample+64 {
			lastSample = tick
			for _, pl := range p.GameState().Participants().Playing() {
				if pl.PlayerPawnEntity() == nil {
					continue
				}
				inventory := make([]int, 0, len(pl.Inventory))
				for id := range pl.Inventory {
					inventory = append(inventory, id)
				}
				sort.Ints(inventory)
				record("PlayerStateSamples", []any{gotvPlayer(pl), pl.EntityID, pl.Position(), pl.CurrPosition, pl.PrevPosition, pl.ViewAngle, pl.FlagState, pl.Health(), pl.Armor(), pl.Team, pl.Alive, pl.Coaching, inventory, gotvWeapon(pl.ActiveWeapon())})
			}
			alive := make([]int, 0)
			for id := range p.GameState().Participants().AliveByEntID() {
				alive = append(alive, id)
			}
			sort.Ints(alive)
			record("AliveSamples", alive)
		}
		flush()
	})
	if err := p.ParseToEnd(); err != nil {
		t.Fatal(err)
	}
	flush()
	t.Logf("tick-zero bootstrap PlayerSpawn events (not golden-compared): %d", bootstrapSpawns)
	result.Frames = p.CurrentFrame()
	result.LastTick = p.GameState().IngameTick()
	result.ScoreT = p.GameState().TeamTerrorists().Score()
	result.ScoreCT = p.GameState().TeamCounterTerrorists().Score()
	for name, h := range hashes {
		result.Digests[name] = hex.EncodeToString(h.Sum(nil))
	}
	return result
}

func gotvPlayer(p *common.Player) any {
	if p == nil {
		return nil
	}
	return []any{p.SteamID64, p.UserID}
}
func gotvWeapon(w *common.Equipment) any {
	if w == nil {
		return nil
	}
	return []any{w.Type, w.EntityId}
}
