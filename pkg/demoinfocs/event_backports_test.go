package demoinfocs

import (
	"bytes"
	"testing"

	"github.com/golang/geo/r3"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/common"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/events"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/msgs2"
	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
	"google.golang.org/protobuf/proto"
)

type eventBackportEntity struct {
	st.Entity
	id   int
	pos  r3.Vector
	pawn uint64
}

func (e eventBackportEntity) ID() int             { return e.id }
func (e eventBackportEntity) Position() r3.Vector { return e.pos }
func (e eventBackportEntity) Property(name string) st.Property {
	if name != "m_hPlayerPawn" {
		panic(name)
	}
	return eventBackportProperty{value: e.pawn}
}

type eventBackportProperty struct {
	st.Property
	value uint64
}

func (p eventBackportProperty) Value() st.PropertyValue {
	return st.PropertyValue{Any: p.value, S2: true}
}

func eventBackportParser(t *testing.T) *parser {
	t.Helper()
	p := NewParser(bytes.NewReader(make([]byte, 16))).(*parser)
	t.Cleanup(func() { p.Close() })
	return p
}

func TestFlashAttributionOutOfOrderAndEmptyDetonation(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{true: "victim before destruction", false: "victim after destruction"}[before], func(t *testing.T) {
			p := eventBackportParser(t)
			victim := &common.Player{EntityID: 3, FlashDuration: 1.25}
			p.gameState.playersByEntityID[3] = victim
			a := &common.GrenadeProjectile{Entity: eventBackportEntity{id: 10}, Thrower: &common.Player{UserID: 1}}
			b := &common.GrenadeProjectile{Entity: eventBackportEntity{id: 20}, Thrower: &common.Player{UserID: 2}}
			p.gameState.flyingFlashbangs = []*FlyingFlashbang{{projectile: a}, {projectile: b}}
			var got []events.FakePlayerFlashed
			p.RegisterEventHandler(func(e events.FakePlayerFlashed) { got = append(got, e) })
			p.processFlyingFlashbangs() // frame zero does not imply a detonation
			if len(p.gameState.flyingFlashbangs) != 2 {
				t.Fatal("airborne flashes removed at frame zero")
			}
			p.currentFrame = 10
			p.markFlashDetonated(b) // second thrown flash detonates first, without victims
			p.processFlyingFlashbangs()
			if len(got) != 0 || len(p.gameState.flyingFlashbangs) != 1 || p.gameState.flyingFlashbangs[0].projectile != a {
				t.Fatal("empty detonation removed the wrong flash")
			}
			p.currentFrame++
			if before {
				p.gameState.flashedEntitiesThisFrame = append(p.gameState.flashedEntitiesThisFrame, 3)
			}
			p.markFlashDetonated(a)
			if !before {
				p.gameState.flashedEntitiesThisFrame = append(p.gameState.flashedEntitiesThisFrame, 3)
			}
			p.processFlyingFlashbangs()
			if len(got) != 1 || got[0].Projectile != a || got[0].Attacker != a.Thrower || got[0].Player != victim || got[0].Duration != 1.25 {
				t.Fatalf("wrong attribution: %+v", got)
			}
			p.processFlyingFlashbangs()
			if len(got) != 1 || len(p.gameState.flyingFlashbangs) != 0 {
				t.Fatal("detonation emitted twice or not removed")
			}
		})
	}
}

func TestSimultaneousFlashDetonations(t *testing.T) {
	p := eventBackportParser(t)
	p.currentFrame = 10
	victim := &common.Player{EntityID: 3, FlashDuration: 2}
	p.gameState.playersByEntityID[3] = victim
	far := &common.GrenadeProjectile{Entity: eventBackportEntity{id: 10, pos: r3.Vector{X: 100}}}
	near := &common.GrenadeProjectile{Entity: eventBackportEntity{id: 20, pos: r3.Vector{X: 5}}}
	p.gameState.flyingFlashbangs = []*FlyingFlashbang{{projectile: far}, {projectile: near}}
	p.markFlashDetonated(far)
	p.markFlashDetonated(near)
	p.gameState.flashedEntitiesThisFrame = []int{3, 999} // unresolved victim is ignored
	var got []events.FakePlayerFlashed
	p.RegisterEventHandler(func(e events.FakePlayerFlashed) { got = append(got, e) })
	p.processFlyingFlashbangs()
	if len(got) != 1 || got[0].Projectile != near {
		t.Fatalf("nearest detonation not selected: %+v", got)
	}
}

func TestThrownGrenadeSnapshotAfterInventoryRemoval(t *testing.T) {
	p := eventBackportParser(t)
	owner := &common.Player{}
	weapon := common.NewEquipment(common.EqSmoke, p.demoInfoProvider)
	weapon.Entity = eventBackportEntity{id: 12}
	weapon.EntityId = 12
	weapon.Owner = owner
	p.gameState.rememberGrenadeWeapon(owner, weapon)
	weapon.Owner = nil
	weapon.Entity = nil // later mutations must not overwrite cached snapshot
	resolved := p.thrownGrenadeInstance(owner, common.EqSmoke)
	if resolved.Entity == nil || resolved.Entity.ID() != 12 || resolved.Owner != owner || resolved.UniqueID2() != weapon.UniqueID2() {
		t.Fatal("missing cached entity/owner or changed identity")
	}
	resolved.Owner = nil
	if p.thrownGrenadeInstance(owner, common.EqSmoke).Owner != owner {
		t.Fatal("projectile mutated shared cache")
	}
	if p.thrownGrenadeInstance(owner, common.EqHE).Entity != nil {
		t.Fatal("reused a different grenade type")
	}
	if p.thrownGrenadeInstance(nil, common.EqSmoke).Owner != nil {
		t.Fatal("invented owner")
	}
	last := common.NewEquipment(common.EqSmoke, p.demoInfoProvider)
	last.Entity = eventBackportEntity{id: 25}
	owner.LastThrownGrenade = last
	if got := p.thrownGrenadeInstance(owner, common.EqSmoke); got.Entity.ID() != 25 || got == last || last.Owner != nil {
		t.Fatal("fork LastThrownGrenade precedence or copy semantics lost")
	}
}

func TestPlayerHurtAttackerPawnFallback(t *testing.T) {
	p := eventBackportParser(t)
	attacker := &common.Player{UserID: 11, Entity: eventBackportEntity{pawn: 1234}}
	known := &common.Player{UserID: 12, Entity: eventBackportEntity{pawn: 5678}}
	p.gameState.playersByUserID[11] = attacker
	p.gameState.playersByUserID[12] = known
	data := map[string]*msgs2.CSVCMsg_GameEventKeyT{
		"attacker": {ValShort: proto.Int32(99)}, "attacker_pawn": {ValLong: proto.Int32(1234)}, "weapon": {ValString: proto.String("ak47")},
	}
	var got events.PlayerHurt
	p.RegisterEventHandler(func(e events.PlayerHurt) { got = e })
	p.gameEventHandler.playerHurt(data)
	if got.Attacker != attacker {
		t.Fatal("pawn fallback did not resolve attacker")
	}
	data["attacker"].ValShort = proto.Int32(12)
	p.gameEventHandler.playerHurt(data)
	if got.Attacker != known {
		t.Fatal("fallback overwrote known user ID")
	}
	data["attacker"].ValShort = proto.Int32(99)
	data["attacker_pawn"].ValLong = proto.Int32(99999)
	p.gameEventHandler.playerHurt(data)
	if got.Attacker != nil {
		t.Fatal("unresolved handle invented an attacker")
	}
}

func TestUnknownMessageWarningUsesEventQueue(t *testing.T) {
	p := eventBackportParser(t)
	p.msgQueue = make(chan any, 8)
	p.msgDispatcher.AddQueues(p.msgQueue)
	var got []events.ParserWarn
	p.RegisterEventHandler(func(w events.ParserWarn) { got = append(got, w) })
	var packed []byte
	bitpos := 0
	add := func(value uint32, n int) {
		for i := 0; i < n; i++ {
			if bitpos/8 >= len(packed) {
				packed = append(packed, 0)
			}
			packed[bitpos/8] |= byte((value>>i)&1) << uint(bitpos%8)
			bitpos++
		}
	}
	const unknown = 999999
	add(48|(unknown&15), 6)
	add(unknown>>4, 28)
	add(0, 8)
	p.handleDemoPacket(&msgs2.CDemoPacket{Data: packed})
	p.msgDispatcher.SyncAllQueues()
	if len(got) != 1 || got[0].Type != events.WarnTypeUnknownProtobufMessage {
		t.Fatalf("warning not delivered through event handlers: %+v", got)
	}
}

type unknownWeaponEntity struct{ st.Entity }

func (unknownWeaponEntity) ID() int { return 999 }
func (unknownWeaponEntity) PropertyValueMust(string) st.PropertyValue {
	return st.PropertyValue{Any: uint64(999999), S2: true}
}
func (unknownWeaponEntity) PropertyValue(string) (st.PropertyValue, bool) {
	return st.PropertyValue{}, false
}
func (unknownWeaponEntity) Property(string) st.Property { return noUpdateProperty{} }
func (unknownWeaponEntity) OnDestroy(func())            {}

type noUpdateProperty struct{ st.Property }

func (noUpdateProperty) OnUpdate(st.PropertyUpdateHandler) {}

func TestUnknownEquipmentWarningUsesEventHandlers(t *testing.T) {
	p := eventBackportParser(t)
	var got []events.ParserWarn
	p.RegisterEventHandler(func(w events.ParserWarn) { got = append(got, w) })
	p.bindWeaponS2(unknownWeaponEntity{})
	if len(got) != 1 || got[0].Type != events.WarnTypeUnknownEquipmentIndex {
		t.Fatalf("missing unknown-equipment warning: %+v", got)
	}
}
