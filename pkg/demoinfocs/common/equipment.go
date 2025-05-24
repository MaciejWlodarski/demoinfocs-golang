package common

import (
	"math"
	"math/rand"
	"strings"

	"github.com/oklog/ulid/v2"

	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

// EquipmentClass is the type for the various EqClassXYZ constants.
type EquipmentClass int

// EquipmentClass constants give information about the type of an equipment (SMG, Rifle, Grenade etc.).
//
// Note: (EquipmentType+99) / 100 = EquipmentClass
const (
	EqClassUnknown   EquipmentClass = 0
	EqClassPistols   EquipmentClass = 1
	EqClassSMG       EquipmentClass = 2
	EqClassHeavy     EquipmentClass = 3
	EqClassRifle     EquipmentClass = 4
	EqClassEquipment EquipmentClass = 5
	EqClassGrenade   EquipmentClass = 6
)

// EquipmentType is the type for the various EqXYZ constants.
type EquipmentType int

// Class returns the class of the equipment.
// E.g. pistol, smg, heavy etc.
func (e EquipmentType) Class() EquipmentClass {
	const classDenominator = 100

	return EquipmentClass((int(e) + classDenominator - 1) / classDenominator)
}

// String returns a human readable name for the equipment.
// E.g. 'AK-47', 'UMP-45', 'Smoke Grenade' etc.
func (e EquipmentType) String() string {
	return eqElementToName[e]
}

// EquipmentType constants give information about what weapon a player has equipped.
const (
	EqUnknown EquipmentType = 0

	// Pistols

	EqP2000        EquipmentType = 1
	EqGlock        EquipmentType = 2
	EqP250         EquipmentType = 3
	EqDeagle       EquipmentType = 4
	EqFiveSeven    EquipmentType = 5
	EqDualBerettas EquipmentType = 6
	EqTec9         EquipmentType = 7
	EqCZ           EquipmentType = 8
	EqUSP          EquipmentType = 9
	EqRevolver     EquipmentType = 10

	// SMGs

	EqMP7   EquipmentType = 101
	EqMP9   EquipmentType = 102
	EqBizon EquipmentType = 103
	EqMac10 EquipmentType = 104
	EqUMP   EquipmentType = 105
	EqP90   EquipmentType = 106
	EqMP5   EquipmentType = 107

	// Heavy

	EqSawedOff EquipmentType = 201
	EqNova     EquipmentType = 202
	EqMag7     EquipmentType = 203 // You should consider using EqSwag7 instead
	EqSwag7    EquipmentType = 203
	EqXM1014   EquipmentType = 204
	EqM249     EquipmentType = 205
	EqNegev    EquipmentType = 206

	// Rifles

	EqGalil  EquipmentType = 301
	EqFamas  EquipmentType = 302
	EqAK47   EquipmentType = 303
	EqM4A4   EquipmentType = 304
	EqM4A1   EquipmentType = 305
	EqScout  EquipmentType = 306
	EqSSG08  EquipmentType = 306
	EqSG556  EquipmentType = 307
	EqSG553  EquipmentType = 307
	EqAUG    EquipmentType = 308
	EqAWP    EquipmentType = 309
	EqScar20 EquipmentType = 310
	EqG3SG1  EquipmentType = 311

	// Equipment

	EqZeus                     EquipmentType = 401
	EqKevlar                   EquipmentType = 402
	EqHelmet                   EquipmentType = 403
	EqBomb                     EquipmentType = 404
	EqKnife                    EquipmentType = 405
	EqDefuseKit                EquipmentType = 406
	EqWorld                    EquipmentType = 407
	EqZoneRepulsor             EquipmentType = 408
	EqShield                   EquipmentType = 409
	EqHeavyAssaultSuit         EquipmentType = 410
	EqNightVision              EquipmentType = 411
	EqHealthShot               EquipmentType = 412
	EqTacticalAwarenessGrenade EquipmentType = 413
	EqFists                    EquipmentType = 414
	EqBreachCharge             EquipmentType = 415
	EqTablet                   EquipmentType = 416
	EqAxe                      EquipmentType = 417
	EqHammer                   EquipmentType = 418
	EqWrench                   EquipmentType = 419
	EqSnowball                 EquipmentType = 420
	EqBumpMine                 EquipmentType = 421

	// Grenades

	EqDecoy      EquipmentType = 501
	EqMolotov    EquipmentType = 502
	EqIncendiary EquipmentType = 503
	EqFlash      EquipmentType = 504
	EqSmoke      EquipmentType = 505
	EqHE         EquipmentType = 506
)

var eqNameToWeapon map[string]EquipmentType

var eqElementToName map[EquipmentType]string

func init() {
	initEqNameToWeapon()
	initEqElementToName()
}

//nolint:funlen
func initEqNameToWeapon() {
	eqNameToWeapon = make(map[string]EquipmentType)

	eqNameToWeapon["ak47"] = EqAK47
	eqNameToWeapon["aug"] = EqAUG
	eqNameToWeapon["awp"] = EqAWP
	eqNameToWeapon["bizon"] = EqBizon
	eqNameToWeapon["c4"] = EqBomb
	eqNameToWeapon["planted_c4"] = EqBomb
	eqNameToWeapon["deagle"] = EqDeagle
	eqNameToWeapon["decoy"] = EqDecoy
	eqNameToWeapon["decoygrenade"] = EqDecoy
	eqNameToWeapon["decoyprojectile"] = EqDecoy
	eqNameToWeapon["decoy_projectile"] = EqDecoy
	eqNameToWeapon["elite"] = EqDualBerettas
	eqNameToWeapon["famas"] = EqFamas
	eqNameToWeapon["fiveseven"] = EqFiveSeven
	eqNameToWeapon["flashbang"] = EqFlash
	eqNameToWeapon["g3sg1"] = EqG3SG1
	eqNameToWeapon["galil"] = EqGalil
	eqNameToWeapon["galilar"] = EqGalil
	eqNameToWeapon["glock"] = EqGlock
	eqNameToWeapon["hegrenade"] = EqHE
	eqNameToWeapon["hkp2000"] = EqP2000
	eqNameToWeapon["incgrenade"] = EqIncendiary
	eqNameToWeapon["incendiarygrenade"] = EqIncendiary
	eqNameToWeapon["m249"] = EqM249
	eqNameToWeapon["m4a1"] = EqM4A4
	eqNameToWeapon["mac10"] = EqMac10
	eqNameToWeapon["mag7"] = EqSwag7
	eqNameToWeapon["molotov"] = EqMolotov
	eqNameToWeapon["molotovgrenade"] = EqMolotov
	eqNameToWeapon["molotovprojectile"] = EqMolotov
	eqNameToWeapon["molotov_projectile"] = EqMolotov
	eqNameToWeapon["mp7"] = EqMP7
	eqNameToWeapon["mp5sd"] = EqMP5
	eqNameToWeapon["mp9"] = EqMP9
	eqNameToWeapon["negev"] = EqNegev
	eqNameToWeapon["nova"] = EqNova
	eqNameToWeapon["p250"] = EqP250
	eqNameToWeapon["p90"] = EqP90
	eqNameToWeapon["sawedoff"] = EqSawedOff
	eqNameToWeapon["scar20"] = EqScar20
	eqNameToWeapon["sg556"] = EqSG556
	eqNameToWeapon["smokegrenade"] = EqSmoke
	eqNameToWeapon["smokegrenadeprojectile"] = EqSmoke
	eqNameToWeapon["smokegrenade_projectile"] = EqSmoke
	eqNameToWeapon["ssg08"] = EqScout
	eqNameToWeapon["taser"] = EqZeus
	eqNameToWeapon["tec9"] = EqTec9
	eqNameToWeapon["ump45"] = EqUMP
	eqNameToWeapon["xm1014"] = EqXM1014
	eqNameToWeapon["m4a1_silencer"] = EqM4A1
	eqNameToWeapon["m4a1_silencer_off"] = EqM4A1
	eqNameToWeapon["cz75a"] = EqCZ
	eqNameToWeapon["usp"] = EqUSP
	eqNameToWeapon["usp_silencer"] = EqUSP
	eqNameToWeapon["usp_silencer_off"] = EqUSP
	eqNameToWeapon["world"] = EqWorld
	eqNameToWeapon["inferno"] = EqIncendiary
	eqNameToWeapon["revolver"] = EqRevolver
	eqNameToWeapon["vest"] = EqKevlar
	eqNameToWeapon["vesthelm"] = EqHelmet
	eqNameToWeapon["defuser"] = EqDefuseKit

	// These don't exist and / or used to crash the game with the give command
	eqNameToWeapon["scar17"] = EqUnknown
	eqNameToWeapon["sensorgrenade"] = EqUnknown
	eqNameToWeapon["mp5navy"] = EqUnknown
	eqNameToWeapon["p228"] = EqUnknown
	eqNameToWeapon["scout"] = EqUnknown
	eqNameToWeapon["sg550"] = EqUnknown
	eqNameToWeapon["sg552"] = EqUnknown // This one still crashes the game :)
	eqNameToWeapon["tmp"] = EqUnknown
	eqNameToWeapon["worldspawn"] = EqWorld
}

//nolint:funlen
func initEqElementToName() {
	eqElementToName = make(map[EquipmentType]string)
	eqElementToName[EqAK47] = "AK-47"
	eqElementToName[EqAUG] = "AUG"
	eqElementToName[EqAWP] = "AWP"
	eqElementToName[EqBizon] = "PP-Bizon"
	eqElementToName[EqBomb] = "C4"
	eqElementToName[EqDeagle] = "Desert Eagle"
	eqElementToName[EqDecoy] = "Decoy Grenade"
	eqElementToName[EqDualBerettas] = "Dual Berettas"
	eqElementToName[EqFamas] = "FAMAS"
	eqElementToName[EqFiveSeven] = "Five-SeveN"
	eqElementToName[EqFlash] = "Flashbang"
	eqElementToName[EqG3SG1] = "G3SG1"
	eqElementToName[EqGalil] = "Galil AR"
	eqElementToName[EqGlock] = "Glock-18"
	eqElementToName[EqHE] = "HE Grenade"
	eqElementToName[EqP2000] = "P2000"
	eqElementToName[EqIncendiary] = "Incendiary Grenade"
	eqElementToName[EqM249] = "M249"
	eqElementToName[EqM4A4] = "M4A4"
	eqElementToName[EqMac10] = "MAC-10"
	eqElementToName[EqSwag7] = "MAG-7"
	eqElementToName[EqMolotov] = "Molotov"
	eqElementToName[EqMP7] = "MP7"
	eqElementToName[EqMP5] = "MP5-SD"
	eqElementToName[EqMP9] = "MP9"
	eqElementToName[EqNegev] = "Negev"
	eqElementToName[EqNova] = "Nova"
	eqElementToName[EqP250] = "P250"
	eqElementToName[EqP90] = "P90"
	eqElementToName[EqSawedOff] = "Sawed-Off"
	eqElementToName[EqScar20] = "SCAR-20"
	eqElementToName[EqSG553] = "SG 553"
	eqElementToName[EqSmoke] = "Smoke Grenade"
	eqElementToName[EqScout] = "SSG 08"
	eqElementToName[EqZeus] = "Zeus x27"
	eqElementToName[EqTec9] = "Tec-9"
	eqElementToName[EqUMP] = "UMP-45"
	eqElementToName[EqXM1014] = "XM1014"
	eqElementToName[EqM4A1] = "M4A1"
	eqElementToName[EqCZ] = "CZ75 Auto"
	eqElementToName[EqUSP] = "USP-S"
	eqElementToName[EqWorld] = "World"
	eqElementToName[EqRevolver] = "R8 Revolver"
	eqElementToName[EqKevlar] = "Kevlar Vest"
	eqElementToName[EqHelmet] = "Kevlar + Helmet"
	eqElementToName[EqDefuseKit] = "Defuse Kit"
	eqElementToName[EqKnife] = "Knife"
	eqElementToName[EqUnknown] = "UNKNOWN"
}

const weaponPrefix = "weapon_"

// MapEquipment creates an EquipmentType from the name of the weapon / equipment.
// Returns EqUnknown if no mapping can be found.
func MapEquipment(eqName string) EquipmentType {
	eqName = strings.TrimPrefix(eqName, weaponPrefix)

	var wep EquipmentType
	if strings.Contains(eqName, "knife") || strings.Contains(eqName, "bayonet") {
		wep = EqKnife
	} else {
		// If the eqName isn't known it will be EqUnknown as that is the default value for EquipmentType
		if strings.HasPrefix(eqName, "m4a1_silencer") {
			wep = EqM4A1
		} else if strings.HasPrefix(eqName, "vesthelm") {
			wep = EqHelmet
		} else {
			for name := range eqNameToWeapon {
				if strings.HasPrefix(eqName, name) || strings.HasSuffix(eqName, name) {
					wep = eqNameToWeapon[name]
					break
				}
			}
		}
	}

	return wep
}

var EquipmentMaxSpeed = map[EquipmentType]int{
	// Pistols
	EqDeagle:       230,
	EqRevolver:     180,
	EqDualBerettas: 240,
	EqFiveSeven:    240,
	EqGlock:        240,
	EqP2000:        240,
	EqUSP:          240,
	EqP250:         240,
	EqCZ:           240,
	EqTec9:         240,

	// SMGs
	EqBizon: 240,
	EqMac10: 240,
	EqMP7:   220,
	EqMP5:   235,
	EqMP9:   240,
	EqP90:   230,
	EqUMP:   230,

	// Heavy – Shotguns & LMGs
	EqMag7:     225,
	EqNova:     220,
	EqSawedOff: 210,
	EqXM1014:   215,
	EqM249:     195,
	EqNegev:    150,

	// Rifles
	EqAK47:   215,
	EqAUG:    220,
	EqFamas:  220,
	EqGalil:  215,
	EqM4A4:   225,
	EqM4A1:   225,
	EqSG553:  210,
	EqSSG08:  230,
	EqAWP:    200,
	EqScar20: 215,
	EqG3SG1:  215,
}

// ZoomLevel contains how far a player is zoomed in.
type ZoomLevel int

// All currently known zoom levels.
const (
	ZoomNone ZoomLevel = 0
	ZoomHalf ZoomLevel = 1
	ZoomFull ZoomLevel = 2
)

// Equipment is a weapon / piece of equipment belonging to a player.
// This also includes the skin and some additional data.
type Equipment struct {
	Type     EquipmentType // The type of weapon which the equipment instantiates.
	Entity   st.Entity     // The game entity instance
	EntityId int
	Owner    *Player // The player carrying the equipment, not necessarily the buyer.
	Skin     *Skin
	State    int

	uniqueID         int64 // Deprecated, use uniqueID2, see UniqueID() for why
	uniqueID2        ulid.ULID
	demoInfoProvider demoInfoProvider
}

// String returns a human readable name for the equipment.
// E.g. 'AK-47', 'UMP-45', 'Smoke Grenade' etc.
func (e *Equipment) String() string {
	return e.Type.String()
}

// Class returns the class of the equipment.
// E.g. pistol, smg, heavy etc.
func (e *Equipment) Class() EquipmentClass {
	return e.Type.Class()
}

// UniqueID returns a randomly generated unique id of the equipment element.
// The unique id is a random int generated internally by this library and can be used to differentiate
// equipment from each other. This is needed because demo-files reuse entity ids.
// Deprecated: Use UniqueID2 instead. Since UniqueID is randomly generated, duplicate IDs are possible.
// See the birthday problem for why repeatedly generating random 64 bit integers is likely to produce a collision.
func (e *Equipment) UniqueID() int64 {
	return e.uniqueID
}

// UniqueID2 returns a unique id of the equipment element that can be sorted efficiently.
// UniqueID2 is a value generated internally by this library and can be used to differentiate
// equipment from each other. This is needed because demo-files reuse entity ids.
// Unlike UniqueID, UniqueID2 is guaranteed to be unique.
func (e *Equipment) UniqueID2() ulid.ULID {
	return e.uniqueID2
}

// AmmoInMagazine returns the ammo left in the magazine.
// Returns 1 for grenades and equipments (Knife, C4...).
func (e *Equipment) AmmoInMagazine() int {
	switch true {
	case e.Class() == EqClassGrenade || e.Class() == EqClassEquipment:
		return 1
	case e.Entity == nil:
		return 0
	default:
		val, ok := e.Entity.PropertyValue("m_iClip1")
		if !ok {
			return -1
		}

		return int(val.S2UInt32())
	}
}

// ZoomLevel returns how far the player has zoomed in on the weapon.
// Only weapons with scopes have a valid zoom level.
func (e *Equipment) ZoomLevel() ZoomLevel {
	if e.Entity == nil {
		return 0
	}

	value, ok := e.Entity.PropertyValue("m_zoomLevel")
	if !ok || value.Any == nil {
		return 0
	}

	return ZoomLevel(value.Int())
}

// AmmoReserve returns the ammo left available for reloading.
// Use AmmoInMagazine() + AmmoReserve() to quickly get the amount of grenades a player owns.
func (e *Equipment) AmmoReserve() int {
	if e.Entity == nil {
		return 0
	}

	if e.Class() == EqClassGrenade {
		if e.Owner == nil {
			return 0
		}

		return e.Owner.GetGrenadeAmmo(e.Type)
	}

	if propVal, ok := e.Entity.PropertyValue("m_pReserveAmmo.0000"); ok && propVal.Any != nil {
		return propVal.Int()
	}
	return 0
}

// RecoilIndex returns the weapon's recoil index
func (e *Equipment) RecoilIndex() float32 {
	if e.Entity == nil {
		return 0
	}

	// if the property doesn't exist we return 0 by default
	val, ok := e.Entity.PropertyValue("m_flRecoilIndex")
	if !ok || val.Any == nil {
		return 0
	}

	return val.Float()
}

// Silenced returns true if weapon is silenced.
func (e *Equipment) Silenced() bool {
	// If entity is nil returns false.
	if e.Entity == nil {
		return false
	}

	prop := e.Entity.Property("m_bSilencerOn")

	return prop.Value().BoolVal()
}

func (e *Equipment) AccuracyPenalty() float32 {
	if e.Entity == nil {
		return 0
	}
	val, ok := e.Entity.PropertyValue("m_fAccuracyPenalty")
	if !ok || val.Any == nil {
		return 0
	}
	return val.Float()
}

func remapValClamped(val, A, B, C, D float64) float64 {
	if A == B {
		if val >= B {
			return D
		}
		return C
	}

	cVal := (val - A) / (B - A)
	if cVal < 0 {
		cVal = 0
	} else if cVal > 1 {
		cVal = 1
	}

	return C + (D-C)*cVal
}

func roundTo(x float64, places int) float64 {
	pow := math.Pow(10, float64(places))
	return math.Round(x*pow) / pow
}

func (e *Equipment) MovementInaccuracyScale() float64 {
	if e.Entity == nil || e.Owner == nil {
		return 0
	}

	const DUCK_SPEED_MODIFIER float64 = 0.34
	const MOVEMENT_CURVE01_EXPONENT float64 = 0.25

	velocity := e.Owner.Velocity()
	speed := roundTo(math.Hypot(velocity.X, velocity.Y), 2)

	maxSpeed := float64(EquipmentMaxSpeed[e.Type])

	movementInaccuracyScale := remapValClamped(
		speed,
		maxSpeed*DUCK_SPEED_MODIFIER,
		maxSpeed*0.95,
		0.0, 1.0,
	)

	if movementInaccuracyScale == 0 {
		return 0
	}

	movementInaccuracyScale = math.Pow(movementInaccuracyScale, MOVEMENT_CURVE01_EXPONENT)
	return movementInaccuracyScale
}

func (e *Equipment) JumpThrow() bool {
	if e.Entity == nil {
		return false
	}
	val, ok := e.Entity.PropertyValue("m_bJumpThrow")
	if !ok || val.Any == nil {
		return false
	}
	return val.BoolVal()
}

func (e *Equipment) ThrowStrength() float32 {
	if e.Entity == nil {
		return 0
	}
	val, ok := e.Entity.PropertyValue("m_flThrowStrength")
	if !ok || val.Any == nil {
		return 0
	}
	return val.Float()
}

func (e *Equipment) ThrowStrengthApproach() float32 {
	if e.Entity == nil {
		return 0
	}
	val, ok := e.Entity.PropertyValue("m_flThrowStrengthApproach")
	if !ok || val.Any == nil {
		return 0
	}
	return val.Float()
}

func (e *Equipment) OwnerHandle() uint64 {
	val, ok := e.Entity.PropertyValue("m_hOwnerEntity")
	if ok {
		return val.Handle()
	}
	return 0
}

type Skin struct {
	ItemId  int32    `json:"item_id"`
	PaintId *uint64  `json:"paint_id"`
	Pattern *int32   `json:"pattern"`
	Float   *float32 `json:"float"`
}

func (e *Equipment) GetSkin() *Skin {
	if e.Entity == nil {
		return nil
	}
	skin := &Skin{}

	val, exists := e.Entity.PropertyValue("m_iItemDefinitionIndex")
	if !exists {
		return nil
	}
	skin.ItemId = int32(val.S2UInt64())

	val, exists = e.Entity.PropertyValue("m_Attributes.0000.m_iRawValue32")
	if !exists || val.Any == nil {
		return skin
	}
	paintId := uint64(math.Round(float64(val.Float())))
	skin.PaintId = &paintId

	val, exists = e.Entity.PropertyValue("m_Attributes.0001.m_iRawValue32")
	if exists && val.Any != nil {
		patter := int32(val.Float())
		skin.Pattern = &patter
	}

	val, exists = e.Entity.PropertyValue("m_Attributes.0002.m_iRawValue32")
	if exists && val.Any != nil {
		skinFloat := val.Float()
		skin.Float = &skinFloat
	}

	return skin
}

func (e *Equipment) ReloadTime() int32 {
	return ReloadTimeMapping[e.Type]
}

func (e *Equipment) DemoInfo() demoInfoProvider {
	return e.demoInfoProvider
}

// NewEquipment creates a new Equipment and sets the UniqueID.
//
// Intended for internal use only.
func NewEquipment(wep EquipmentType, demoInfoProvider demoInfoProvider) *Equipment {
	return &Equipment{
		Type:             wep,
		State:            -1,
		uniqueID:         rand.Int63(),
		uniqueID2:        ulid.Make(),
		demoInfoProvider: demoInfoProvider,
	} //nolint:gosec
}

var equipmentToAlternative = map[EquipmentType]EquipmentType{
	EqP2000:     EqUSP,
	EqP250:      EqCZ, // for old demos where the CZ was the alternative for the P250
	EqFiveSeven: EqCZ,
	EqTec9:      EqCZ,
	EqDeagle:    EqRevolver,
	EqMP7:       EqMP5,
	EqM4A4:      EqM4A1,
}

// EquipmentAlternative returns the EquipmentType of the alternatively equippable weapon.
// E.g. returns EquipmentAlternative(EqP2000) returns EqUSP.
// Only works one way (default-to-alternative) as the Five-Seven and Tec-9 both map to the CZ-75.
func EquipmentAlternative(eq EquipmentType) EquipmentType {
	return equipmentToAlternative[eq]
}

var ReloadTimeMapping = map[EquipmentType]int32{
	EqAUG:          99,
	EqAWP:          129,
	EqCZ:           99,
	EqDeagle:       56,
	EqDualBerettas: 186,
	EqFamas:        105,
	EqFiveSeven:    60,
	EqG3SG1:        167,
	EqGalil:        75,
	EqGlock:        60,
	EqM249:         239,
	EqM4A1:         88,
	EqM4A4:         88,
	EqMac10:        82,
	EqMag7:         69,
	EqMP5:          129,
	EqMP7:          92,
	EqMP9:          56,
	EqNegev:        246,
	EqNova:         78,
	EqP2000:        62,
	EqP250:         60,
	EqP90:          126,
	EqBizon:        75,
	EqRevolver:     126,
	EqScar20:       90,
	EqSSG08:        126,
	EqSawedOff:     211,
	EqTec9:         86,
	EqUMP:          97,
	EqUSP:          62,
	EqXM1014:       203,
}

// Indexes are available in the game file located at 'scripts/items/items_game.txt'.
var EquipmentIndexMapping = map[uint64]EquipmentType{
	1:   EqDeagle,                   // weapon_deagle
	2:   EqDualBerettas,             // weapon_elite
	3:   EqFiveSeven,                // weapon_fiveseven
	4:   EqGlock,                    // weapon_glock
	7:   EqAK47,                     // weapon_ak47
	8:   EqAUG,                      // weapon_aug
	9:   EqAWP,                      // weapon_awp
	10:  EqFamas,                    // weapon_famas
	11:  EqG3SG1,                    // weapon_g3sg1
	13:  EqGalil,                    // weapon_galilar
	14:  EqM249,                     // weapon_m249
	16:  EqM4A4,                     // weapon_m4a1
	17:  EqMac10,                    // weapon_mac10
	19:  EqP90,                      // weapon_p90
	20:  EqZoneRepulsor,             // weapon_zone_repulsor
	23:  EqMP5,                      // weapon_mp5sd
	24:  EqUMP,                      // weapon_ump45
	25:  EqXM1014,                   // weapon_xm1014
	26:  EqBizon,                    // weapon_bizon
	27:  EqMag7,                     // weapon_mag7
	28:  EqNegev,                    // weapon_negev
	29:  EqSawedOff,                 // weapon_sawedoff
	30:  EqTec9,                     // weapon_tec9
	31:  EqZeus,                     // weapon_taser
	32:  EqP2000,                    // weapon_hkp2000
	33:  EqMP7,                      // weapon_mp7
	34:  EqMP9,                      // weapon_mp9
	35:  EqNova,                     // weapon_nova
	36:  EqP250,                     // weapon_p250
	37:  EqShield,                   // weapon_shield
	38:  EqScar20,                   // weapon_scar20
	39:  EqSG556,                    // weapon_sg556
	40:  EqSSG08,                    // weapon_ssg08
	41:  EqKnife,                    // weapon_knifegg
	42:  EqKnife,                    // weapon_knife
	43:  EqFlash,                    // weapon_flashbang
	44:  EqHE,                       // weapon_hegrenade
	45:  EqSmoke,                    // weapon_smokegrenade
	46:  EqMolotov,                  // weapon_molotov
	47:  EqDecoy,                    // weapon_decoy
	48:  EqIncendiary,               // weapon_incgrenade
	49:  EqBomb,                     // weapon_c4
	50:  EqKevlar,                   // item_kevlar
	51:  EqHelmet,                   // item_assaultsuit
	52:  EqHeavyAssaultSuit,         // item_heavyassaultsuit
	54:  EqNightVision,              // item_nvg
	55:  EqDefuseKit,                // item_defuser
	56:  EqDefuseKit,                // item_cutters https://developer.valvesoftware.com/wiki/Item_cutters
	57:  EqHealthShot,               // weapon_healthshot (Medi-Shot)
	59:  EqKnife,                    // weapon_knife_t
	60:  EqM4A1,                     // weapon_m4a1_silencer
	61:  EqUSP,                      // weapon_usp_silencer
	63:  EqCZ,                       // weapon_cz75a
	64:  EqRevolver,                 // weapon_revolver
	68:  EqTacticalAwarenessGrenade, // weapon_tagrenade
	69:  EqFists,                    // weapon_fists
	70:  EqBreachCharge,             // weapon_breachcharge
	72:  EqTablet,                   // weapon_tablet
	74:  EqFists,                    // weapon_melee
	75:  EqAxe,                      // weapon_axe
	76:  EqHammer,                   // weapon_hammer
	78:  EqWrench,                   // weapon_spanner
	80:  EqKnife,                    // weapon_knife_ghost
	81:  EqBomb,                     // weapon_firebomb
	82:  EqDecoy,                    // weapon_diversion
	83:  EqHE,                       // weapon_frag_grenade
	84:  EqSnowball,                 // weapon_snowball
	85:  EqBumpMine,                 // weapon_bumpmine
	500: EqKnife,                    // weapon_bayonet
	503: EqKnife,                    // weapon_knife_css
	505: EqKnife,                    // weapon_knife_flip
	506: EqKnife,                    // weapon_knife_gut
	507: EqKnife,                    // weapon_knife_karambit
	508: EqKnife,                    // weapon_knife_m9_bayonet
	509: EqKnife,                    // weapon_knife_tactical
	512: EqKnife,                    // weapon_knife_falchion
	514: EqKnife,                    // weapon_knife_survival_bowie
	515: EqKnife,                    // weapon_knife_butterfly
	516: EqKnife,                    // weapon_knife_push
	517: EqKnife,                    // weapon_knife_cord
	518: EqKnife,                    // weapon_knife_canis
	519: EqKnife,                    // weapon_knife_ursus
	520: EqKnife,                    // weapon_knife_gypsy_jackknife
	521: EqKnife,                    // weapon_knife_outdoor
	522: EqKnife,                    // weapon_knife_stiletto
	523: EqKnife,                    // weapon_knife_widowmaker
	525: EqKnife,                    // weapon_knife_skeleton
	526: EqKnife,                    // weapon_knife_kukri
}
