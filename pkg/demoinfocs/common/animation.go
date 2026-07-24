package common

import (
	"fmt"
	"math"
	"reflect"

	"github.com/golang/geo/r3"

	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/constants"
	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

const (
	animationPropDynamic       = "CBodyComponent.m_SerializePoseRecipeAG2Dynamic"
	animationPropSlots         = "CBodyComponent.m_SerializePoseRecipeAG2Slots"
	animationPropActiveSlot    = "CBodyComponent.m_nSerializePoseRecipeAG2ActiveSlot"
	animationPropRecipeVersion = "CBodyComponent.m_nSerializePoseRecipeVersionAG2"
	animationPropGraph         = "CBodyComponent.m_hGraphDefinitionAG2"
	animationPropPrimaryGraph  = "CBodyComponent.m_primaryGraphId"
	animationPropEyeAngles     = "m_angEyeAngles"
	animationPropBodyAngles    = "CBodyComponent.m_angRotation"
	animationPropDuckAmount    = "m_pMovementServices.m_flDuckAmount"
	animationPropLifeState     = "m_lifeState"
	animationPropHealth        = "m_iHealth"
	animationPropFlags         = "m_fFlags"
	animationPropShotsFired    = "m_iShotsFired"
	animationPropActiveWeapon  = "m_pWeaponServices.m_hActiveWeapon"
	animationPropSecondary     = "CBodyComponent.m_vecSecondarySkeletons"
	animationPropSecondarySlot = "CBodyComponent.m_vecSecondarySkeletonSlotIDs"
	animationPropModel         = "CBodyComponent.m_hModel"

	animationSecondaryIndexMask   = uint64((1 << 14) - 1)
	animationSecondarySerialShift = 14
)

// AnimationInput is a complete typed snapshot of the network state consumed by
// CS2's AnimGraph2 for one player. It intentionally preserves unknown bytes in
// the serialized recipe and topology payloads.
type AnimationInput struct {
	Identity   AnimationIdentity
	Controller AnimationEntity
	Pawn       AnimationPawn
	Weapon     AnimationWeapon
	Movement   AnimationMovement
	View       AnimationView
	AG2        AnimationAG2
	Secondary  AnimationSecondarySkeletons
}

// AnimationState is kept as an alternative, semantically equivalent name for
// callers that use the snapshot as state rather than evaluator input.
type AnimationState = AnimationInput

type AnimationIdentity struct {
	SteamID64   uint64
	UserID      int
	Name        string
	Team        Team
	IsBot       bool
	IsConnected bool
	IsAlive     bool
}

// AnimationEntity identifies a networked entity at this snapshot.
type AnimationEntity struct {
	Present  bool
	EntityID int
	Serial   int
	Class    string
}

type AnimationPawn struct {
	AnimationEntity
	Origin    [3]float32
	Health    int
	LifeState uint64
	IsAlive   bool
	Flags     uint64
	Dormant   *bool
}

type AnimationWeapon struct {
	AnimationEntity
	Handle              uint64
	ItemDefinitionIndex int64
	ItemDefinitionValid bool
	Clip1               int64
	Clip1Valid          bool
	State               int64
	StateValid          bool
	InReload            bool
	InReloadValid       bool
}

type AnimationMovement struct {
	DuckAmount float32
	ShotsFired int64
}

type AnimationView struct {
	EyeAngles  [3]float32
	BodyAngles [3]float32
}

// AnimationRawBytes distinguishes a missing value from a present empty payload.
// Data is always owned by the snapshot.
type AnimationRawBytes struct {
	Valid   bool
	Present bool
	Data    []byte
}

type AnimationTopologySlot struct {
	Present  bool
	Topology []byte
}

type AnimationAG2 struct {
	Dynamic              AnimationRawBytes
	TopologySlots        []AnimationTopologySlot
	TopologySlotsPresent bool
	ActiveTopology       AnimationRawBytes
	GraphDefinition      uint64
	PrimaryGraphID       *uint64
	RecipeVersion        int64
	ActiveSlot           int64
}

type AnimationSecondarySkeletonEntry struct {
	NetworkIndex      int
	BuilderIndex      int
	SlotID            *string
	Handle            uint64
	HandleEntityIndex uint64
	HandleSerial      uint64
	EntityResolved    bool
	EntityID          *int
	EntitySerial      *int
	EntitySerialMatch bool
	ModelConfigHandle *uint64
}

type AnimationSecondarySkeletons struct {
	Present     bool
	PawnEntity  int
	PawnSerial  int
	LengthMatch bool
	Entries     []AnimationSecondarySkeletonEntry
}

// AnimationInput returns a typed, immutable-by-ownership snapshot of all
// network state required to reproduce this player's AnimGraph2 inputs. A player
// without a pawn is a valid lifecycle state and returns a snapshot with
// Pawn.Present set to false. A pawn with a missing or malformed required AG2
// property returns an error.
func (p *Player) AnimationInput() (AnimationInput, error) {
	if p == nil {
		return AnimationInput{}, fmt.Errorf("animation input: nil player")
	}

	result := AnimationInput{
		Identity: AnimationIdentity{
			SteamID64:   p.SteamID64,
			UserID:      p.UserID,
			Name:        p.Name,
			Team:        p.Team,
			IsBot:       p.IsBot,
			IsConnected: p.IsConnected,
		},
		Controller: animationEntityFromEntity(p.Entity),
		Secondary:  AnimationSecondarySkeletons{Entries: []AnimationSecondarySkeletonEntry{}},
	}

	pawn, err := p.animationPawnEntity()
	if err != nil {
		return AnimationInput{}, err
	}
	if pawn == nil {
		return result, nil
	}

	required := make(map[string]any, 10)
	for _, name := range []string{
		animationPropDynamic, animationPropSlots, animationPropActiveSlot,
		animationPropRecipeVersion, animationPropGraph, animationPropEyeAngles,
		animationPropBodyAngles, animationPropDuckAmount, animationPropLifeState,
		animationPropHealth, animationPropFlags, animationPropShotsFired,
	} {
		value, ok := animationPropertyAnyOK(pawn, name)
		if !ok {
			return AnimationInput{}, fmt.Errorf("animation input: required property %s is missing", name)
		}
		required[name] = value
	}

	activeSlot, err := animationRequiredInt64(required, animationPropActiveSlot)
	if err != nil {
		return AnimationInput{}, err
	}
	recipeVersion, err := animationRequiredInt64(required, animationPropRecipeVersion)
	if err != nil {
		return AnimationInput{}, err
	}
	health, err := animationRequiredInt64(required, animationPropHealth)
	if err != nil {
		return AnimationInput{}, err
	}
	lifeState, err := animationRequiredUint64(required, animationPropLifeState)
	if err != nil {
		return AnimationInput{}, err
	}
	flags, err := animationRequiredUint64(required, animationPropFlags)
	if err != nil {
		return AnimationInput{}, err
	}
	duckAmount, err := animationRequiredFloat64(required, animationPropDuckAmount)
	if err != nil {
		return AnimationInput{}, err
	}
	shotsFired, err := animationRequiredInt64(required, animationPropShotsFired)
	if err != nil {
		return AnimationInput{}, err
	}
	eyeAngles, err := animationRequiredAngle(required, animationPropEyeAngles)
	if err != nil {
		return AnimationInput{}, err
	}
	bodyAngles, err := animationRequiredAngle(required, animationPropBodyAngles)
	if err != nil {
		return AnimationInput{}, err
	}
	graphDefinition, err := animationRequiredUint64(required, animationPropGraph)
	if err != nil {
		return AnimationInput{}, err
	}
	dynamic, ok := animationBytesFromAny(required[animationPropDynamic])
	if !ok {
		return AnimationInput{}, fmt.Errorf("animation input: property %s has unsupported byte representation %T", animationPropDynamic, required[animationPropDynamic])
	}
	slots, err := animationTopologySlots(pawn, required[animationPropSlots])
	if err != nil {
		return AnimationInput{}, err
	}

	var primaryGraphIDPointer *uint64
	if primaryGraphValue, primaryGraphPresent := animationPropertyAnyOK(pawn, animationPropPrimaryGraph); primaryGraphPresent {
		primaryGraphID, hasPrimaryGraphID := animationUint64FromAny(primaryGraphValue)
		if !hasPrimaryGraphID {
			return AnimationInput{}, fmt.Errorf("animation input: property %s has unsupported type %T", animationPropPrimaryGraph, primaryGraphValue)
		}
		primaryGraphIDPointer = &primaryGraphID
	}
	activeTopology := AnimationRawBytes{Valid: true}
	if activeSlot >= 0 && int(activeSlot) < len(slots) && slots[activeSlot].Present {
		activeTopology = AnimationRawBytes{Valid: true, Present: true, Data: animationCloneBytes(slots[activeSlot].Topology)}
	}

	origin := pawn.Position()
	isAlive := p.Team >= 2 && lifeState == 0 && health > 0
	result.Identity.IsAlive = isAlive
	result.Pawn = AnimationPawn{
		AnimationEntity: animationEntityFromEntity(pawn),
		Origin:          [3]float32{float32(origin.X), float32(origin.Y), float32(origin.Z)},
		Health:          int(health),
		LifeState:       lifeState,
		IsAlive:         isAlive,
		Flags:           flags,
	}
	if active, ok := pawn.(interface{ IsActive() bool }); ok {
		dormant := !active.IsActive()
		result.Pawn.Dormant = &dormant
	}
	result.Movement = AnimationMovement{DuckAmount: float32(duckAmount), ShotsFired: shotsFired}
	result.View = AnimationView{EyeAngles: eyeAngles, BodyAngles: bodyAngles}
	result.AG2 = AnimationAG2{
		Dynamic:              AnimationRawBytes{Valid: true, Present: true, Data: dynamic},
		TopologySlots:        slots,
		TopologySlotsPresent: true,
		ActiveTopology:       activeTopology,
		GraphDefinition:      graphDefinition,
		PrimaryGraphID:       primaryGraphIDPointer,
		RecipeVersion:        recipeVersion,
		ActiveSlot:           activeSlot,
	}
	result.Weapon, err = p.animationWeapon(pawn)
	if err != nil {
		return AnimationInput{}, err
	}
	result.Secondary, err = p.animationSecondary(pawn)
	if err != nil {
		return AnimationInput{}, err
	}
	return result, nil
}

func (p *Player) animationPawnEntity() (st.Entity, error) {
	if p.Entity == nil {
		return nil, nil
	}
	pawnValue, pawnPresent := animationPropertyAnyOK(p.Entity, "m_hPawn")
	if !pawnPresent {
		return nil, nil
	}
	pawnHandle, ok := animationUint64FromAny(pawnValue)
	if !ok {
		return nil, fmt.Errorf("animation input: controller property m_hPawn has unsupported type %T", pawnValue)
	}
	if pawnHandle == constants.InvalidEntityHandleSource2 {
		return nil, nil
	}
	playerPawnValue, playerPawnPresent := animationPropertyAnyOK(p.Entity, "m_hPlayerPawn")
	if !playerPawnPresent {
		return nil, nil
	}
	playerPawnHandle, ok := animationUint64FromAny(playerPawnValue)
	if !ok {
		return nil, fmt.Errorf("animation input: controller property m_hPlayerPawn has unsupported type %T", playerPawnValue)
	}
	if p.demoInfoProvider == nil {
		return nil, fmt.Errorf("animation input: player has no demo info provider")
	}
	return p.demoInfoProvider.FindEntityByHandle(playerPawnHandle), nil
}

// AnimationState is an alias for AnimationInput for callers that prefer a
// state-oriented name.
func (p *Player) AnimationState() (AnimationState, error) {
	return p.AnimationInput()
}

// Clone returns a deep copy. In particular, no raw packet bytes, topology
// bytes, optional pointers, or secondary-skeleton pointers are shared.
func (input AnimationInput) Clone() AnimationInput {
	copyInput := input
	copyInput.AG2.Dynamic.Data = animationCloneBytes(input.AG2.Dynamic.Data)
	copyInput.AG2.ActiveTopology.Data = animationCloneBytes(input.AG2.ActiveTopology.Data)
	copyInput.AG2.TopologySlots = make([]AnimationTopologySlot, len(input.AG2.TopologySlots))
	for index, slot := range input.AG2.TopologySlots {
		copyInput.AG2.TopologySlots[index] = AnimationTopologySlot{Present: slot.Present, Topology: animationCloneBytes(slot.Topology)}
	}
	if input.AG2.PrimaryGraphID != nil {
		value := *input.AG2.PrimaryGraphID
		copyInput.AG2.PrimaryGraphID = &value
	}
	if input.Pawn.Dormant != nil {
		value := *input.Pawn.Dormant
		copyInput.Pawn.Dormant = &value
	}
	copyInput.Secondary.Entries = make([]AnimationSecondarySkeletonEntry, len(input.Secondary.Entries))
	for index, entry := range input.Secondary.Entries {
		copyInput.Secondary.Entries[index] = animationCloneSecondaryEntry(entry)
	}
	return copyInput
}

func (p *Player) animationWeapon(pawn st.Entity) (AnimationWeapon, error) {
	value, present := animationPropertyAnyOK(pawn, animationPropActiveWeapon)
	if !present {
		return AnimationWeapon{}, nil
	}
	handle, ok := animationUint64FromAny(value)
	if !ok {
		return AnimationWeapon{}, fmt.Errorf("animation input: weapon handle %s has unsupported type %T", animationPropActiveWeapon, value)
	}
	entity := p.demoInfoProvider.FindEntityByHandle(handle)
	if entity == nil {
		return AnimationWeapon{Handle: handle}, nil
	}
	item, itemValid, err := animationOptionalInt64(entity, "m_iItemDefinitionIndex")
	if err != nil {
		return AnimationWeapon{}, err
	}
	clip, clipValid, err := animationOptionalInt64(entity, "m_iClip1")
	if err != nil {
		return AnimationWeapon{}, err
	}
	state, stateValid, err := animationOptionalInt64(entity, "m_iState")
	if err != nil {
		return AnimationWeapon{}, err
	}
	reload, reloadValid, err := animationOptionalBool(entity, "m_bInReload")
	if err != nil {
		return AnimationWeapon{}, err
	}
	return AnimationWeapon{
		AnimationEntity:     animationEntityFromEntity(entity),
		Handle:              handle,
		ItemDefinitionIndex: item,
		ItemDefinitionValid: itemValid,
		Clip1:               clip,
		Clip1Valid:          clipValid,
		State:               state,
		StateValid:          stateValid,
		InReload:            reload,
		InReloadValid:       reloadValid,
	}, nil
}

func (p *Player) animationSecondary(pawn st.Entity) (AnimationSecondarySkeletons, error) {
	handlesValue, handlesPresent := animationPropertyAnyOK(pawn, animationPropSecondary)
	slotsValue, slotsPresent := animationPropertyAnyOK(pawn, animationPropSecondarySlot)
	handles := []uint64{}
	if handlesPresent {
		var err error
		handles, err = animationUint64Slice(handlesValue)
		if err != nil {
			return AnimationSecondarySkeletons{}, fmt.Errorf("animation input: %s: %w", animationPropSecondary, err)
		}
	}
	slots := []string{}
	if slotsPresent {
		var err error
		slots, err = animationStringSlice(slotsValue)
		if err != nil {
			return AnimationSecondarySkeletons{}, fmt.Errorf("animation input: %s: %w", animationPropSecondarySlot, err)
		}
	}
	result := AnimationSecondarySkeletons{
		Present:     handlesPresent || slotsPresent,
		PawnEntity:  pawn.ID(),
		PawnSerial:  pawn.SerialNum(),
		LengthMatch: len(handles) == len(slots),
		Entries:     make([]AnimationSecondarySkeletonEntry, 0, len(handles)),
	}
	for networkIndex := len(handles) - 1; networkIndex >= 0; networkIndex-- {
		handle := handles[networkIndex]
		entry := AnimationSecondarySkeletonEntry{
			NetworkIndex:      networkIndex,
			BuilderIndex:      len(result.Entries),
			Handle:            handle,
			HandleEntityIndex: handle & animationSecondaryIndexMask,
			HandleSerial:      handle >> animationSecondarySerialShift,
		}
		if networkIndex < len(slots) {
			value := slots[networkIndex]
			entry.SlotID = &value
		}
		if entity := p.demoInfoProvider.FindEntityByHandle(handle); entity != nil {
			entityID, entitySerial := entity.ID(), entity.SerialNum()
			entry.EntityID = &entityID
			entry.EntitySerial = &entitySerial
			entry.EntitySerialMatch = uint64(entitySerial) == entry.HandleSerial
			entry.EntityResolved = entry.EntitySerialMatch
			if entry.EntityResolved {
				if rawModel, present := animationPropertyAnyOK(entity, animationPropModel); present {
					model, ok := animationUint64FromAny(rawModel)
					if !ok {
						return AnimationSecondarySkeletons{}, fmt.Errorf("animation input: secondary entity %d property %s has unsupported type %T", entity.ID(), animationPropModel, rawModel)
					}
					entry.ModelConfigHandle = &model
				}
			}
		}
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func animationEntityFromEntity(entity st.Entity) AnimationEntity {
	if entity == nil {
		return AnimationEntity{}
	}
	class := ""
	if serverClass := entity.ServerClass(); serverClass != nil {
		class = serverClass.Name()
	}
	return AnimationEntity{Present: true, EntityID: entity.ID(), Serial: entity.SerialNum(), Class: class}
}

func animationTopologySlots(pawn st.Entity, value any) ([]AnimationTopologySlot, error) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || (reflected.Kind() != reflect.Array && reflected.Kind() != reflect.Slice) {
		return nil, fmt.Errorf("animation input: %s has unsupported slot representation %T", animationPropSlots, value)
	}
	result := make([]AnimationTopologySlot, reflected.Len())
	for index := 0; index < reflected.Len(); index++ {
		name := fmt.Sprintf("%s.%04d.m_topology", animationPropSlots, index)
		raw, present := animationPropertyAnyOK(pawn, name)
		if !present {
			continue
		}
		topology, ok := animationBytesFromAny(raw)
		if !ok {
			return nil, fmt.Errorf("animation input: property %s has unsupported byte representation %T", name, raw)
		}
		result[index] = AnimationTopologySlot{Present: true, Topology: topology}
	}
	return result, nil
}

func animationPropertyAnyOK(entity st.Entity, name string) (any, bool) {
	if entity == nil {
		return nil, false
	}
	property := entity.Property(name)
	if property == nil {
		return nil, false
	}
	return property.Value().Any, true
}

func animationBytesFromAny(value any) ([]byte, bool) {
	switch typed := value.(type) {
	case []byte:
		return animationCloneBytes(typed), true
	case []any:
		result := make([]byte, len(typed))
		for index, item := range typed {
			number, ok := animationUint64FromAny(item)
			if !ok || number > math.MaxUint8 {
				return nil, false
			}
			result[index] = byte(number)
		}
		return result, true
	default:
		return nil, false
	}
}

func animationCloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func animationAngleFromAny(value any) ([3]float32, bool) {
	switch typed := value.(type) {
	case r3.Vector:
		return [3]float32{float32(typed.X), float32(typed.Y), float32(typed.Z)}, true
	case []float32:
		if len(typed) < 3 {
			return [3]float32{}, false
		}
		return [3]float32{typed[0], typed[1], typed[2]}, true
	case []float64:
		if len(typed) < 3 {
			return [3]float32{}, false
		}
		return [3]float32{float32(typed[0]), float32(typed[1]), float32(typed[2])}, true
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || (reflected.Kind() != reflect.Array && reflected.Kind() != reflect.Slice) || reflected.Len() < 3 {
		return [3]float32{}, false
	}
	var result [3]float32
	for index := range result {
		number, ok := animationFloat64FromAny(reflected.Index(index).Interface())
		if !ok {
			return [3]float32{}, false
		}
		result[index] = float32(number)
	}
	return result, true
}

func animationUint64Slice(value any) ([]uint64, error) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || (reflected.Kind() != reflect.Array && reflected.Kind() != reflect.Slice) {
		return nil, fmt.Errorf("expected array or slice, got %T", value)
	}
	result := make([]uint64, 0, reflected.Len())
	for index := 0; index < reflected.Len(); index++ {
		number, ok := animationUint64FromAny(reflected.Index(index).Interface())
		if !ok {
			return nil, fmt.Errorf("entry %d has unsupported type %T", index, reflected.Index(index).Interface())
		}
		result = append(result, number)
	}
	return result, nil
}

func animationStringSlice(value any) ([]string, error) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || (reflected.Kind() != reflect.Array && reflected.Kind() != reflect.Slice) {
		return nil, fmt.Errorf("expected array or slice, got %T", value)
	}
	result := make([]string, reflected.Len())
	for index := range result {
		text, ok := reflected.Index(index).Interface().(string)
		if !ok {
			return nil, fmt.Errorf("entry %d has unsupported type %T", index, reflected.Index(index).Interface())
		}
		result[index] = text
	}
	return result, nil
}

func animationUint64FromAny(value any) (uint64, bool) {
	if value == nil {
		return 0, false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflected.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number := reflected.Int()
		return uint64(number), number >= 0
	case reflect.Float32, reflect.Float64:
		number := reflected.Float()
		if math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number >= 18446744073709551616.0 || math.Trunc(number) != number {
			return 0, false
		}
		return uint64(number), true
	default:
		return 0, false
	}
}

func animationInt64FromAny(value any) (int64, bool) {
	if value == nil {
		return 0, false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		number := reflected.Uint()
		if number > math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	case reflect.Float32, reflect.Float64:
		number := reflected.Float()
		if math.IsNaN(number) || math.IsInf(number, 0) || number < math.MinInt64 || number >= 9223372036854775808.0 || math.Trunc(number) != number {
			return 0, false
		}
		return int64(number), true
	default:
		return 0, false
	}
}

func animationFloat64FromAny(value any) (float64, bool) {
	if value == nil {
		return 0, false
	}
	reflected := reflect.ValueOf(value)
	var number float64
	switch reflected.Kind() {
	case reflect.Float32, reflect.Float64:
		number = reflected.Float()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number = float64(reflected.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		number = float64(reflected.Uint())
	default:
		return 0, false
	}
	return number, !math.IsNaN(number) && !math.IsInf(number, 0)
}

func animationBoolFromAny(value any) (bool, bool) {
	if value == nil {
		return false, false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Bool:
		return reflected.Bool(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int() != 0, true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflected.Uint() != 0, true
	default:
		return false, false
	}
}

func animationRequiredInt64(values map[string]any, name string) (int64, error) {
	if value, ok := animationInt64FromAny(values[name]); ok {
		return value, nil
	}
	return 0, fmt.Errorf("animation input: required property %s has unsupported type %T", name, values[name])
}

func animationRequiredUint64(values map[string]any, name string) (uint64, error) {
	if value, ok := animationUint64FromAny(values[name]); ok {
		return value, nil
	}
	return 0, fmt.Errorf("animation input: required property %s has unsupported type %T", name, values[name])
}

func animationRequiredFloat64(values map[string]any, name string) (float64, error) {
	if value, ok := animationFloat64FromAny(values[name]); ok {
		return value, nil
	}
	return 0, fmt.Errorf("animation input: required property %s has unsupported type %T", name, values[name])
}

func animationRequiredAngle(values map[string]any, name string) ([3]float32, error) {
	if value, ok := animationAngleFromAny(values[name]); ok {
		return value, nil
	}
	return [3]float32{}, fmt.Errorf("animation input: required property %s has unsupported type %T", name, values[name])
}

func animationOptionalInt64(entity st.Entity, name string) (int64, bool, error) {
	value, present := animationPropertyAnyOK(entity, name)
	if !present {
		return 0, false, nil
	}
	number, ok := animationInt64FromAny(value)
	if !ok {
		return 0, false, fmt.Errorf("animation input: weapon property %s has unsupported type %T", name, value)
	}
	return number, true, nil
}

func animationOptionalBool(entity st.Entity, name string) (bool, bool, error) {
	value, present := animationPropertyAnyOK(entity, name)
	if !present {
		return false, false, nil
	}
	result, ok := animationBoolFromAny(value)
	if !ok {
		return false, false, fmt.Errorf("animation input: weapon property %s has unsupported type %T", name, value)
	}
	return result, true, nil
}

func animationCloneSecondaryEntry(entry AnimationSecondarySkeletonEntry) AnimationSecondarySkeletonEntry {
	copyEntry := entry
	if entry.SlotID != nil {
		value := *entry.SlotID
		copyEntry.SlotID = &value
	}
	if entry.EntityID != nil {
		value := *entry.EntityID
		copyEntry.EntityID = &value
	}
	if entry.EntitySerial != nil {
		value := *entry.EntitySerial
		copyEntry.EntitySerial = &value
	}
	if entry.ModelConfigHandle != nil {
		value := *entry.ModelConfigHandle
		copyEntry.ModelConfigHandle = &value
	}
	return copyEntry
}
