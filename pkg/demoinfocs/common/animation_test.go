package common

import (
	"reflect"
	"strings"
	"testing"

	"github.com/golang/geo/r3"

	bit "github.com/markus-wa/demoinfocs-golang/v4/internal/bitread"
	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

func TestPlayerAnimationInputCopiesRawStateAndPreservesNullableWeaponFields(t *testing.T) {
	const (
		pawnHandle      = uint64(3<<14 | 42)
		weaponHandle    = uint64(4<<14 | 21)
		secondaryHandle = uint64(7<<14 | 9)
	)
	dynamic := []byte{1, 2, 3}
	topology := []byte{4, 5, 6}
	pawn := newAnimationTestEntity(42, 3, r3.Vector{X: 10, Y: 20, Z: 30}, map[string]any{
		animationPropDynamic:                    dynamic,
		animationPropSlots:                      []any{struct{}{}},
		animationPropSlots + ".0000.m_topology": topology,
		animationPropActiveSlot:                 int32(0),
		animationPropRecipeVersion:              int64(17),
		animationPropGraph:                      uint64(99),
		animationPropPrimaryGraph:               uint64(100),
		animationPropEyeAngles:                  []float32{1, 2, 3},
		animationPropBodyAngles:                 []float32{4, 5, 6},
		animationPropDuckAmount:                 float32(0.5),
		animationPropLifeState:                  uint64(0),
		animationPropHealth:                     int32(100),
		animationPropFlags:                      uint64(9),
		animationPropShotsFired:                 int32(2),
		animationPropActiveWeapon:               weaponHandle,
		animationPropSecondary:                  []any{secondaryHandle},
		animationPropSecondarySlot:              []any{"weapon_back"},
	})
	weapon := newAnimationTestEntity(21, 4, r3.Vector{}, map[string]any{
		"m_iItemDefinitionIndex": int32(0),
		"m_iState":               int64(3),
		"m_bInReload":            false,
	})
	secondary := newAnimationTestEntity(9, 7, r3.Vector{}, map[string]any{
		animationPropModel: uint64(1234),
	})
	controller := newAnimationTestEntity(1, 1, r3.Vector{}, map[string]any{
		"m_hPawn":       pawnHandle,
		"m_hPlayerPawn": pawnHandle,
	})
	provider := &animationTestProvider{entities: map[uint64]st.Entity{
		pawnHandle: pawn, weaponHandle: weapon, secondaryHandle: secondary,
	}}
	player := &Player{
		demoInfoProvider: provider,
		SteamID64:        76561198000000000,
		UserID:           12,
		Name:             "Zireael",
		Team:             TeamCounterTerrorists,
		IsConnected:      true,
		Entity:           controller,
	}

	input, err := player.AnimationInput()
	if err != nil {
		t.Fatalf("AnimationInput() error = %v", err)
	}
	if !input.Pawn.Present || input.Pawn.EntityID != 42 || input.Pawn.Serial != 3 {
		t.Fatalf("unexpected pawn lifecycle: %#v", input.Pawn)
	}
	if input.Pawn.Origin != [3]float32{10, 20, 30} || input.Pawn.Health != 100 || !input.Pawn.IsAlive {
		t.Fatalf("unexpected pawn state: %#v", input.Pawn)
	}
	if input.Pawn.Dormant == nil || *input.Pawn.Dormant {
		t.Fatalf("active pawn dormant state: %#v", input.Pawn.Dormant)
	}
	pawn.active = false
	dormantInput, err := player.AnimationInput()
	if err != nil {
		t.Fatalf("AnimationInput() for dormant pawn error = %v", err)
	}
	if dormantInput.Pawn.Dormant == nil || !*dormantInput.Pawn.Dormant {
		t.Fatalf("inactive pawn dormant state: %#v", dormantInput.Pawn.Dormant)
	}
	pawn.active = true
	if !input.AG2.Dynamic.Valid || !input.AG2.Dynamic.Present || !reflect.DeepEqual(input.AG2.Dynamic.Data, dynamic) {
		t.Fatalf("dynamic payload was not captured: %#v", input.AG2.Dynamic)
	}
	if len(input.AG2.TopologySlots) != 1 || !reflect.DeepEqual(input.AG2.TopologySlots[0].Topology, topology) {
		t.Fatalf("topology slots were not captured: %#v", input.AG2.TopologySlots)
	}
	if !reflect.DeepEqual(input.AG2.ActiveTopology.Data, topology) || input.AG2.PrimaryGraphID == nil || *input.AG2.PrimaryGraphID != 100 {
		t.Fatalf("active topology or graph IDs were not captured: %#v", input.AG2)
	}
	if !input.Weapon.Present || input.Weapon.Handle != weaponHandle || !input.Weapon.ItemDefinitionValid || input.Weapon.ItemDefinitionIndex != 0 {
		t.Fatalf("zero-valued present weapon property was not preserved: %#v", input.Weapon)
	}
	if input.Weapon.Clip1Valid || !input.Weapon.StateValid || !input.Weapon.InReloadValid || input.Weapon.InReload {
		t.Fatalf("nullable weapon properties were not preserved: %#v", input.Weapon)
	}
	if !input.Secondary.Present || len(input.Secondary.Entries) != 1 {
		t.Fatalf("secondary skeleton was not captured: %#v", input.Secondary)
	}
	entry := input.Secondary.Entries[0]
	if entry.SlotID == nil || *entry.SlotID != "weapon_back" || !entry.EntityResolved || entry.ModelConfigHandle == nil || *entry.ModelConfigHandle != 1234 {
		t.Fatalf("secondary skeleton entry was not resolved: %#v", entry)
	}
	state, err := player.AnimationState()
	if err != nil {
		t.Fatalf("AnimationState() error = %v", err)
	}
	if !reflect.DeepEqual(input, state) {
		t.Fatalf("AnimationState() differs from AnimationInput()")
	}

	dynamic[0] = 99
	topology[0] = 99
	if input.AG2.Dynamic.Data[0] != 1 || input.AG2.TopologySlots[0].Topology[0] != 4 || input.AG2.ActiveTopology.Data[0] != 4 {
		t.Fatalf("snapshot aliases source raw bytes: %#v", input.AG2)
	}
}

func TestPlayerAnimationInputRejectsMissingAndMalformedState(t *testing.T) {
	pawn := newAnimationTestEntity(42, 3, r3.Vector{}, map[string]any{
		animationPropDynamic: []byte{1},
	})
	player := animationTestPlayer(pawn, nil)
	_, err := player.AnimationInput()
	if err == nil || !strings.Contains(err.Error(), animationPropSlots) || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing slots error = %v, want property-specific missing error", err)
	}

	pawn = animationTestPawn(map[string]any{
		animationPropDynamic:    []byte{1},
		animationPropSlots:      []any{},
		animationPropActiveSlot: "not-an-integer",
	})
	player = animationTestPlayer(pawn, nil)
	_, err = player.AnimationInput()
	if err == nil || !strings.Contains(err.Error(), animationPropActiveSlot) || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("malformed active-slot error = %v, want property-specific type error", err)
	}

	pawn = animationTestPawn(map[string]any{animationPropLifeState: "not-an-unsigned-integer"})
	player = animationTestPlayer(pawn, nil)
	_, err = player.AnimationInput()
	if err == nil || !strings.Contains(err.Error(), animationPropLifeState) || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("malformed lifecycle error = %v, want property-specific type error", err)
	}

	player = animationTestPlayer(animationTestPawn(nil), nil)
	player.Entity = newAnimationTestEntity(1, 1, r3.Vector{}, map[string]any{
		"m_hPawn": "not-a-handle",
	})
	_, err = player.AnimationInput()
	if err == nil || !strings.Contains(err.Error(), "m_hPawn") || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("malformed pawn handle error = %v, want property-specific type error", err)
	}

	weapon := newAnimationTestEntity(21, 4, r3.Vector{}, map[string]any{"m_iClip1": "invalid"})
	pawn = animationTestPawn(map[string]any{animationPropActiveWeapon: uint64(4<<14 | 21)})
	player = animationTestPlayer(pawn, map[uint64]st.Entity{uint64(4<<14 | 21): weapon})
	_, err = player.AnimationInput()
	if err == nil || !strings.Contains(err.Error(), "m_iClip1") || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("malformed nullable weapon value error = %v, want property-specific type error", err)
	}
}

func TestAnimationInputCloneDoesNotShareMutableState(t *testing.T) {
	graphID := uint64(4)
	dormant := true
	slot := "slot"
	entityID := 8
	serial := 2
	model := uint64(9)
	input := AnimationInput{
		Pawn: AnimationPawn{Dormant: &dormant},
		AG2: AnimationAG2{
			Dynamic:        AnimationRawBytes{Data: []byte{1}},
			ActiveTopology: AnimationRawBytes{Data: []byte{2}},
			TopologySlots:  []AnimationTopologySlot{{Present: true, Topology: []byte{3}}},
			PrimaryGraphID: &graphID,
		},
		Secondary: AnimationSecondarySkeletons{Entries: []AnimationSecondarySkeletonEntry{{
			SlotID: &slot, EntityID: &entityID, EntitySerial: &serial, ModelConfigHandle: &model,
		}}},
	}
	clone := input.Clone()
	clone.AG2.Dynamic.Data[0] = 11
	clone.AG2.ActiveTopology.Data[0] = 12
	clone.AG2.TopologySlots[0].Topology[0] = 13
	*clone.AG2.PrimaryGraphID = 14
	*clone.Pawn.Dormant = false
	*clone.Secondary.Entries[0].SlotID = "changed"
	*clone.Secondary.Entries[0].EntityID = 15
	*clone.Secondary.Entries[0].EntitySerial = 16
	*clone.Secondary.Entries[0].ModelConfigHandle = 17

	if input.AG2.Dynamic.Data[0] != 1 || input.AG2.ActiveTopology.Data[0] != 2 || input.AG2.TopologySlots[0].Topology[0] != 3 || *input.AG2.PrimaryGraphID != 4 || !*input.Pawn.Dormant {
		t.Fatalf("Clone() aliases raw input state: %#v", input)
	}
	entry := input.Secondary.Entries[0]
	if *entry.SlotID != "slot" || *entry.EntityID != 8 || *entry.EntitySerial != 2 || *entry.ModelConfigHandle != 9 {
		t.Fatalf("Clone() aliases secondary state: %#v", entry)
	}
}

func animationTestPawn(overrides map[string]any) *animationTestEntity {
	props := map[string]any{
		animationPropDynamic:       []byte{1, 2},
		animationPropSlots:         []any{},
		animationPropActiveSlot:    int32(0),
		animationPropRecipeVersion: int32(1),
		animationPropGraph:         uint64(2),
		animationPropEyeAngles:     []float32{1, 2, 3},
		animationPropBodyAngles:    []float32{4, 5, 6},
		animationPropDuckAmount:    float32(0),
		animationPropLifeState:     uint64(0),
		animationPropHealth:        int32(100),
		animationPropFlags:         uint64(1),
		animationPropShotsFired:    int32(0),
	}
	for key, value := range overrides {
		props[key] = value
	}
	return newAnimationTestEntity(42, 3, r3.Vector{}, props)
}

func animationTestPlayer(pawn st.Entity, entities map[uint64]st.Entity) *Player {
	const pawnHandle = uint64(3<<14 | 42)
	if entities == nil {
		entities = map[uint64]st.Entity{}
	}
	entities[pawnHandle] = pawn
	controller := newAnimationTestEntity(1, 1, r3.Vector{}, map[string]any{
		"m_hPawn":       pawnHandle,
		"m_hPlayerPawn": pawnHandle,
	})
	return &Player{
		demoInfoProvider: &animationTestProvider{entities: entities},
		Team:             TeamCounterTerrorists,
		IsConnected:      true,
		Entity:           controller,
	}
}

type animationTestProvider struct {
	entities map[uint64]st.Entity
}

func (p *animationTestProvider) IngameTick() int                       { return 0 }
func (p *animationTestProvider) TickRate() float64                     { return 64 }
func (p *animationTestProvider) FindPlayerByHandle(uint64) *Player     { return nil }
func (p *animationTestProvider) FindPlayerByPawnHandle(uint64) *Player { return nil }
func (p *animationTestProvider) PlayerResourceEntity() st.Entity       { return nil }
func (p *animationTestProvider) FindWeaponByEntityID(int) *Equipment   { return nil }
func (p *animationTestProvider) FindEntityByHandle(handle uint64) st.Entity {
	return p.entities[handle]
}
func (p *animationTestProvider) TeamState(Team) *TeamState               { return nil }
func (p *animationTestProvider) PlayersAliveByEntityID() map[int]*Player { return nil }
func (p *animationTestProvider) Bomb() *Bomb                             { return nil }
func (p *animationTestProvider) Weapons() map[int]*Equipment             { return nil }

type animationTestEntity struct {
	id       int
	serial   int
	active   bool
	position r3.Vector
	props    map[string]any
}

func newAnimationTestEntity(id, serial int, position r3.Vector, props map[string]any) *animationTestEntity {
	return &animationTestEntity{id: id, serial: serial, active: true, position: position, props: props}
}

func (e *animationTestEntity) ServerClass() st.ServerClass { return animationTestServerClass{} }
func (e *animationTestEntity) ID() int                     { return e.id }
func (e *animationTestEntity) SerialNum() int              { return e.serial }
func (e *animationTestEntity) IsActive() bool              { return e.active }
func (e *animationTestEntity) Properties() []st.Property   { return nil }
func (e *animationTestEntity) Property(name string) st.Property {
	if _, ok := e.props[name]; !ok {
		return nil
	}
	return animationTestProperty{name: name, value: e.props[name]}
}
func (e *animationTestEntity) BindProperty(string, any, st.PropertyValueType) {}
func (e *animationTestEntity) PropertyValue(name string) (st.PropertyValue, bool) {
	value, ok := e.props[name]
	return st.PropertyValue{Any: value, S2: true}, ok
}
func (e *animationTestEntity) PropertyValueMust(name string) st.PropertyValue {
	value, ok := e.PropertyValue(name)
	if !ok {
		panic("missing property: " + name)
	}
	return value
}
func (e *animationTestEntity) ApplyUpdate(*bit.BitReader)       {}
func (e *animationTestEntity) Position() r3.Vector              { return e.position }
func (e *animationTestEntity) OnPositionUpdate(func(r3.Vector)) {}
func (e *animationTestEntity) OnDestroy(func())                 {}
func (e *animationTestEntity) Destroy()                         {}
func (e *animationTestEntity) OnCreateFinished(func())          {}

type animationTestProperty struct {
	name  string
	value any
}

func (p animationTestProperty) Name() string { return p.name }
func (p animationTestProperty) Value() st.PropertyValue {
	return st.PropertyValue{Any: p.value, S2: true}
}
func (animationTestProperty) Type() st.PropertyType             { return 0 }
func (animationTestProperty) ArrayElementType() st.PropertyType { return 0 }
func (animationTestProperty) OnUpdate(st.PropertyUpdateHandler) {}
func (animationTestProperty) Bind(any, st.PropertyValueType)    {}

type animationTestServerClass struct{}

func (animationTestServerClass) ID() int                                      { return 0 }
func (animationTestServerClass) Name() string                                 { return "CTestPawn" }
func (animationTestServerClass) DataTableID() int                             { return 0 }
func (animationTestServerClass) DataTableName() string                        { return "" }
func (animationTestServerClass) BaseClasses() []st.ServerClass                { return nil }
func (animationTestServerClass) PropertyEntries() []string                    { return nil }
func (animationTestServerClass) PropertyEntryDefinitions() []st.PropertyEntry { return nil }
func (animationTestServerClass) OnEntityCreated(st.EntityCreatedHandler)      {}
func (animationTestServerClass) String() string                               { return "CTestPawn" }
