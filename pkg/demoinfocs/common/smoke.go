package common

import (
	"fmt"

	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

type Smoke struct {
	Entity         st.Entity
	IsActive       bool
	ActivationTick int
	VoxelFrameData []uint8

	demoInfoProvider demoInfoProvider
	thrower          *Player
}

// Thrower returns the player who threw the smoke grenade.
// Could be nil if the player disconnected after throwing it.
func (smk *Smoke) Thrower() *Player {
	if smk.thrower != nil {
		return smk.thrower
	}

	handleProp := smk.Entity.Property("m_hOwnerEntity").Value()
	return smk.demoInfoProvider.FindPlayerByPawnHandle(handleProp.Handle())
}

func (smk *Smoke) Voxel() []uint8 {
	voxels := make([]uint8, 0)

	for i := 0; i < 10000; i++ {
		val := smk.Entity.Property("m_VoxelFrameData." + fmt.Sprintf("%04d", i)).Value()
		if val.Any == nil {
			break
		}
		voxels = append(voxels, uint8(val.S2UInt64()))
	}
	return voxels
}

func (smk *Smoke) ExpirationTick() int {
	if !smk.IsActive {
		return -1
	}
	return smk.ActivationTick + 1412
}

func NewSmoke(demoInfoProvider demoInfoProvider, entity st.Entity, thrower *Player) *Smoke {
	return &Smoke{
		Entity:           entity,
		IsActive:         false,
		ActivationTick:   -1,
		demoInfoProvider: demoInfoProvider,
		thrower:          thrower,
	}
}
