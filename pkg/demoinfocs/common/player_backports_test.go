package common

import (
	"github.com/golang/geo/r3"
	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
	"testing"
)

type playerBackportEntity struct {
	st.Entity
	values map[string]any
}

func (e playerBackportEntity) PropertyValue(name string) (st.PropertyValue, bool) {
	value, ok := e.values[name]
	return st.PropertyValue{Any: value, S2: true}, ok
}

type playerBackportProvider struct {
	demoInfoProvider
	pawn st.Entity
}

func (p playerBackportProvider) FindEntityByHandle(handle uint64) st.Entity { return p.pawn }

func TestPlayerBackportAccessors(t *testing.T) {
	for _, player := range []*Player{nil, {}} {
		if player.PlayerPawnEntity() != nil || player.EquipmentValueCurrent() != 0 || player.ActiveWeaponID() != 0 || player.FlashbangCount() != 0 || player.ViewmodelFOV() != 0 || player.ViewmodelOffset() != (r3.Vector{}) {
			t.Fatal("missing player/entity should return zero values")
		}
	}
	pawn := playerBackportEntity{values: map[string]any{}}
	p := &Player{
		Entity:           playerBackportEntity{values: map[string]any{"m_hPawn": uint64(7), "m_hPlayerPawn": uint64(7)}},
		demoInfoProvider: playerBackportProvider{pawn: pawn},
	}
	if p.EquipmentValueCurrent() != 0 || p.ViewmodelFOV() != 0 || p.ViewmodelOffset() != (r3.Vector{}) {
		t.Fatal("missing properties should return zero")
	}
	pawn.values["m_unCurrentEquipmentValue"] = uint64(4200)
	pawn.values["m_pWeaponServices.m_hActiveWeapon"] = uint64(12)
	pawn.values["m_pWeaponServices.m_iAmmo.0014"] = uint64(2)
	pawn.values["m_flViewmodelOffsetX"] = float32(1.5)
	pawn.values["m_flViewmodelOffsetY"] = float32(-2)
	pawn.values["m_flViewmodelOffsetZ"] = float32(3)
	pawn.values["m_flViewmodelFOV"] = float32(68)
	if p.EquipmentValueCurrent() != 4200 || p.ActiveWeaponID() != 12 || p.FlashbangCount() != 2 || p.ViewmodelFOV() != 68 || p.ViewmodelOffset() != (r3.Vector{X: 1.5, Y: -2, Z: 3}) {
		t.Fatal("incorrect player accessor values")
	}
}
