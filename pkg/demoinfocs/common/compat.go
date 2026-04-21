package common

import (
	"math"

	"github.com/golang/geo/r3"
)

type Position struct {
	Tick     int
	Position r3.Vector
}

func (p *Player) DemoInfo() demoInfoProvider {
	return p.demoInfoProvider
}

func (p *Player) GetTeamState() *TeamState {
	if p == nil {
		return nil
	}

	return p.TeamState
}

func (p *Player) ControlledPawn() *Player {
	if p == nil || p.Entity == nil || !p.IsControllingBot() {
		return p
	}

	playerPawn, exists := p.Entity.PropertyValue("m_hOriginalControllerOfCurrentPawn")
	if !exists {
		return p
	}

	return p.demoInfoProvider.FindPlayerByHandle(playerPawn.UInt64())
}

func (p *Player) Controller() *Player {
	if p == nil || p.Entity == nil {
		return p
	}

	playerPawn, exists := p.Entity.PropertyValue("m_hOriginalControllerOfCurrentPawn")
	if !exists || !p.IsBot {
		return p
	}

	controller := p.demoInfoProvider.FindPlayerByHandle(playerPawn.UInt64())
	if controller == nil {
		return p
	}

	return controller
}

func (p *Player) LifeState() int {
	return int(getUInt64(p.PlayerPawnEntity(), "m_lifeState"))
}

func (p *Player) HasBomb() bool {
	return p == p.demoInfoProvider.Bomb().Carrier
}

func (p *Player) MainWeapon() *Equipment {
	if p == nil {
		return nil
	}

	maxClass := 0
	var weapon *Equipment
	for _, wep := range p.Inventory {
		class := int(wep.Type.Class())
		if class >= 1 && class <= 4 && class > maxClass {
			maxClass = class
			weapon = wep
		}

		if weapon == nil && wep.Type == EqKnife {
			weapon = wep
		}
	}

	return weapon
}

func (p *Player) PrimaryWeapon() *Equipment {
	for _, wep := range p.Inventory {
		class := int(wep.Type.Class())
		if class >= 2 && class <= 4 {
			return wep
		}
	}

	return nil
}

func (p *Player) SecondaryWeapon() *Equipment {
	for _, wep := range p.Inventory {
		if wep.Class() == EqClassPistols {
			return wep
		}
	}

	return nil
}

func (p *Player) HEGrenades() int {
	return int(getUInt64(p.PlayerPawnEntity(), "m_pWeaponServices.m_iAmmo.0013"))
}

func (p *Player) Flashbangs() int {
	return int(getUInt64(p.PlayerPawnEntity(), "m_pWeaponServices.m_iAmmo.0014"))
}

func (p *Player) SmokeGrenades() int {
	return int(getUInt64(p.PlayerPawnEntity(), "m_pWeaponServices.m_iAmmo.0015"))
}

func (p *Player) Molotovs() int {
	pawnEntity := p.PlayerPawnEntity()
	if pawnEntity == nil {
		return 0
	}

	val := int(getUInt64(pawnEntity, "m_pWeaponServices.m_iAmmo.0016"))
	if val == 0 {
		return 0
	}

	for _, wep := range p.Inventory {
		if wep.Type == EqMolotov {
			return val
		}

		if wep.Type == EqIncendiary {
			return 0
		}
	}

	if p.Team == TeamTerrorists {
		return val
	}

	return 0
}

func (p *Player) IncendiaryGrenades() int {
	pawnEntity := p.PlayerPawnEntity()
	if pawnEntity == nil {
		return 0
	}

	val := int(getUInt64(pawnEntity, "m_pWeaponServices.m_iAmmo.0016"))
	if val == 0 {
		return 0
	}

	for _, wep := range p.Inventory {
		if wep.Type == EqIncendiary {
			return val
		}

		if wep.Type == EqMolotov {
			return 0
		}
	}

	if p.Team == TeamCounterTerrorists {
		return val
	}

	return 0
}

func (p *Player) DecoyGrenades() int {
	return int(getUInt64(p.PlayerPawnEntity(), "m_pWeaponServices.m_iAmmo.0017"))
}

func (p *Player) PublicLevel() int {
	return getInt(p.Entity, "m_pInventoryServices.m_nPersonaDataPublicLevel")
}

func (p *Player) PublicCommendsLeader() int {
	return getInt(p.Entity, "m_pInventoryServices.m_nPersonaDataPublicCommendsLeader")
}

func (p *Player) PublicCommendsTeacher() int {
	return getInt(p.Entity, "m_pInventoryServices.m_nPersonaDataPublicCommendsTeacher")
}

func (p *Player) PublicCommendsFriendly() int {
	return getInt(p.Entity, "m_pInventoryServices.m_nPersonaDataPublicCommendsFriendly")
}

func (p *Player) XpTrailLevel() int {
	return getInt(p.Entity, "m_pInventoryServices.m_nPersonaDataXpTrailLevel")
}

func (p *Player) Ranking() int {
	return p.Rank()
}

func (p *Player) RankingPredictedWin() int {
	return getInt(p.Entity, "m_iCompetitiveRankingPredicted_Win")
}

func (p *Player) RankingPredictedLoss() int {
	return getInt(p.Entity, "m_iCompetitiveRankingPredicted_Loss")
}

func (p *Player) RankingPredictedTie() int {
	return getInt(p.Entity, "m_iCompetitiveRankingPredicted_Tie")
}

func (p *Player) Velocity() r3.Vector {
	if p == nil {
		return r3.Vector{}
	}

	posCurr := p.CurrPosition
	posPrev := p.PrevPosition
	if posCurr == nil || posPrev == nil {
		return r3.Vector{}
	}

	currentTick := p.demoInfoProvider.IngameTick()
	if currentTick-posCurr.Tick > 1 {
		return r3.Vector{}
	}

	deltaTicks := posCurr.Tick - posPrev.Tick
	if deltaTicks <= 0 {
		return r3.Vector{}
	}

	return r3.Vector{
		X: (posCurr.Position.X - posPrev.Position.X) * 64.0,
		Y: (posCurr.Position.Y - posPrev.Position.Y) * 64.0,
		Z: (posCurr.Position.Z - posPrev.Position.Z) * 64.0,
	}
}

func (p *Player) LeftHand() bool {
	return getBool(p.PlayerPawnEntity(), "m_bLeftHanded")
}

func (p *Player) ViewModel() *ViewModel {
	pawn := p.PlayerPawnEntity()
	return &ViewModel{
		LeftHand: p.LeftHand(),
		OffsetX:  getFloat(pawn, "m_flViewmodelOffsetX"),
		OffsetY:  getFloat(pawn, "m_flViewmodelOffsetY"),
		OffsetZ:  getFloat(pawn, "m_flViewmodelOffsetZ"),
		FOV:      getFloat(pawn, "m_flViewmodelFOV"),
	}
}

type ViewModel struct {
	LeftHand bool    `json:"left_hand"`
	OffsetX  float32 `json:"offset_x"`
	OffsetY  float32 `json:"offset_y"`
	OffsetZ  float32 `json:"offset_z"`
	FOV      float32 `json:"fov"`
}

type Skin struct {
	ItemId  int32    `json:"item_id"`
	PaintId *uint64  `json:"paint_id"`
	Pattern *int32   `json:"pattern"`
	Float   *float32 `json:"float"`
}

func (e *Equipment) GetSkin() *Skin {
	if e == nil || e.Entity == nil {
		return nil
	}

	skin := &Skin{}

	val, exists := e.Entity.PropertyValue("m_iItemDefinitionIndex")
	if !exists {
		return nil
	}
	skin.ItemId = int32(val.UInt64())

	val, exists = e.Entity.PropertyValue("m_Attributes.0000.m_iRawValue32")
	if !exists || val.Any == nil {
		return skin
	}

	paintID := uint64(math.Round(float64(val.Float())))
	skin.PaintId = &paintID

	val, exists = e.Entity.PropertyValue("m_Attributes.0001.m_iRawValue32")
	if exists && val.Any != nil {
		pattern := int32(val.Float())
		skin.Pattern = &pattern
	}

	val, exists = e.Entity.PropertyValue("m_Attributes.0002.m_iRawValue32")
	if exists && val.Any != nil {
		skinFloat := val.Float()
		skin.Float = &skinFloat
	}

	return skin
}

func (e *Equipment) JumpThrow() bool {
	if e == nil || e.Entity == nil {
		return false
	}

	val, ok := e.Entity.PropertyValue("m_bJumpThrow")
	if !ok || val.Any == nil {
		return false
	}

	return val.BoolVal()
}

func (e *Equipment) ThrowStrength() float32 {
	if e == nil || e.Entity == nil {
		return 0
	}

	val, ok := e.Entity.PropertyValue("m_flThrowStrength")
	if !ok || val.Any == nil {
		return 0
	}

	return val.Float()
}

func (e *Equipment) AccuracyPenalty() float32 {
	if e == nil || e.Entity == nil {
		return 0
	}

	val, ok := e.Entity.PropertyValue("m_fAccuracyPenalty")
	if !ok || val.Any == nil {
		return 0
	}

	return val.Float()
}

func remapValClamped(val, a, b, c, d float64) float64 {
	if a == b {
		if val >= b {
			return d
		}
		return c
	}

	cVal := (val - a) / (b - a)
	if cVal < 0 {
		cVal = 0
	} else if cVal > 1 {
		cVal = 1
	}

	return c + (d-c)*cVal
}

func roundTo(x float64, places int) float64 {
	pow := math.Pow(10, float64(places))
	return math.Round(x*pow) / pow
}

func (e *Equipment) MovementInaccuracyScale() float64 {
	if e == nil || e.Entity == nil || e.Owner == nil {
		return 0
	}

	const duckSpeedModifier float64 = 0.34
	const movementCurve01Exponent float64 = 0.25

	velocity := e.Owner.Velocity()
	speed := roundTo(math.Hypot(velocity.X, velocity.Y), 2)
	maxSpeed := float64(EquipmentMaxSpeed[e.Type])

	movementInaccuracyScale := remapValClamped(
		speed,
		maxSpeed*duckSpeedModifier,
		maxSpeed*0.95,
		0.0, 1.0,
	)
	if movementInaccuracyScale == 0 {
		return 0
	}

	return math.Pow(movementInaccuracyScale, movementCurve01Exponent)
}

func (e *Equipment) DemoInfo() demoInfoProvider {
	return e.demoInfoProvider
}

func (e *Equipment) PrevOwner() *Player {
	if e == nil || e.Entity == nil {
		return nil
	}

	val, ok := e.Entity.PropertyValue("m_hPrevOwner")
	if !ok {
		return nil
	}

	return e.demoInfoProvider.FindPlayerByPawnHandle(val.Handle())
}

func (g *GrenadeProjectile) DemoInfo() demoInfoProvider {
	return g.demoInfoProvider
}

func (g *Bomb) DemoInfo() demoInfoProvider {
	return g.demoInfoProvider
}

func (inf *Inferno) DemoInfo() demoInfoProvider {
	return inf.demoInfoProvider
}
