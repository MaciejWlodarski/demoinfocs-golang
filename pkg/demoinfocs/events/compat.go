package events

import (
	"github.com/golang/geo/r3"

	common "github.com/markus-wa/demoinfocs-golang/v5/pkg/demoinfocs/common"
)

type PlayerSpawn struct {
	Player *common.Player
}

type PlayerMove struct {
	Player   *common.Player
	Position r3.Vector
}

type PlayerViewAngleChange struct {
	Player    *common.Player
	ViewAngle r3.Vector
}

type JumpThrow struct {
	Player         *common.Player
	WeaponInstance *common.Equipment
}

type FakeWeaponFire struct {
	Shooter *common.Player
	Weapon  *common.Equipment
}

type WeaponReloadBegin struct {
	Player *common.Player
}

type WeaponReloadEnd struct {
	Player  *common.Player
	Success bool
}

type ItemStateUpdate struct {
	State int
	Owner *common.Player
	Item  *common.Equipment
}

type ItemNewOwner struct {
	Owner *common.Player
	Item  *common.Equipment
}

type ItemDroped struct {
	Owner *common.Player
	Item  *common.Equipment
}

type DefuseKitUpdate struct {
	Player *common.Player
	HasKit bool
}

type BombOwnerUpdate struct {
	NewOwner  *common.Player
	PrevOwner *common.Player
}

type HelmetUpdate struct {
	Player    *common.Player
	HasHelmet bool
}

type ArmorUpdate struct {
	Player *common.Player
	Armor  int
}

type GrenadeUpdate struct {
	Player   *common.Player
	Type     common.EquipmentType
	Quantity int
}

type ActiveWeaponUpdate struct {
	Player *common.Player
	Weapon *common.Equipment
}

type MoneyUpdate struct {
	Player *common.Player
	Money  int
}

type KillsUpdate struct {
	Player *common.Player
	Kills  int
}

type DeathsUpdate struct {
	Player *common.Player
	Deaths int
}

type HandSwitch struct {
	Player *common.Player
	Left   bool
}

type FakeSmokeStart struct {
	GrenadeEvent
}

type InfernoFireStart struct {
	Inferno *common.Inferno
	Index   int
	Fire    *common.Fire
}

type Timeout struct {
	TeamState *common.TeamState
	Tech      bool
}

type FakePlayerFlashed struct {
	Player     *common.Player
	Attacker   *common.Player
	Projectile *common.GrenadeProjectile
	Duration   float32
}
