package common

import (
	"testing"

	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

type classificationEntity struct {
	st.Entity
	values map[string]any
}

func (e classificationEntity) Property(name string) st.Property {
	if _, ok := e.values[name]; ok {
		return classificationProperty{}
	}
	return nil
}

func (e classificationEntity) PropertyValue(name string) (st.PropertyValue, bool) {
	value, ok := e.values[name]
	return st.PropertyValue{Any: value, S2: true}, ok
}

func (e classificationEntity) PropertyValueMust(name string) st.PropertyValue {
	value, ok := e.PropertyValue(name)
	if !ok {
		panic("missing property: " + name)
	}
	return value
}

type classificationProperty struct{ st.Property }

type classificationProvider struct {
	demoInfoProvider
	pawn st.Entity
}

func (p classificationProvider) FindEntityByHandle(uint64) st.Entity { return p.pawn }

func TestIsCoach(t *testing.T) {
	var nilPlayer *Player
	if nilPlayer.IsCoach() || IsCoach(nilPlayer) {
		t.Fatal("nil player cannot be a coach")
	}
	if (&Player{}).IsCoach() {
		t.Fatal("player without a controller cannot be a coach")
	}
	for _, tc := range []struct {
		name, tag string
		coaching  bool
		want      bool
	}{
		{name: "coaching property", coaching: true, want: true},
		{name: "plain coach tag", tag: "[COACH]", want: true},
		{name: "team coach tag", tag: "[TEAM COACH]", want: true},
		{name: "ordinary tag", tag: "[TEAM]"},
		{name: "missing opening bracket", tag: "TEAM COACH]"},
		{name: "missing space", tag: "[TEAMCOACH]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			player := &Player{Coaching: tc.coaching, Entity: classificationEntity{values: map[string]any{"m_szClan": tc.tag}}}
			if got := player.IsCoach(); got != tc.want || IsCoach(player) != got {
				t.Fatalf("IsCoach() = %v, want %v; package wrapper agrees: %v", got, tc.want, IsCoach(player) == got)
			}
		})
	}
}

func TestIsDuckingOrTransitioning(t *testing.T) {
	var nilPlayer *Player
	if nilPlayer.IsDuckingOrTransitioning() || IsDuckingOrTransitioning(nilPlayer) {
		t.Fatal("nil player cannot be ducking")
	}
	if (&Player{}).IsDuckingOrTransitioning() {
		t.Fatal("player without a pawn cannot be ducking")
	}
	for _, tc := range []struct {
		name   string
		flags  uint64
		values map[string]any
		want   bool
	}{
		{name: "fully ducked", flags: flDucking, want: true},
		{name: "ducking transition", values: map[string]any{"m_pMovementServices.m_flDuckAmount": float32(0.5), "m_pMovementServices.m_bDesiresDuck": true}, want: true},
		{name: "unducking transition", values: map[string]any{"m_pMovementServices.m_flDuckAmount": float32(0.5), "m_pMovementServices.m_bDesiresDuck": false}, want: true},
		{name: "no transition with complete properties", flags: flAnimDucking, values: map[string]any{"m_pMovementServices.m_flDuckAmount": float32(0), "m_pMovementServices.m_bDesiresDuck": true}},
		{name: "missing transition properties uses flag", flags: flAnimDucking, want: true},
		{name: "empty transition property uses flag", flags: flAnimDucking, values: map[string]any{"m_pMovementServices.m_flDuckAmount": nil, "m_pMovementServices.m_bDesiresDuck": true}, want: true},
		{name: "standing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pawnValues := map[string]any{"m_fFlags": tc.flags}
			for key, value := range tc.values {
				pawnValues[key] = value
			}
			player := &Player{
				Entity:           classificationEntity{values: map[string]any{"m_hPawn": uint64(7), "m_hPlayerPawn": uint64(7)}},
				demoInfoProvider: classificationProvider{pawn: classificationEntity{values: pawnValues}},
			}
			if got := player.IsDuckingOrTransitioning(); got != tc.want || IsDuckingOrTransitioning(player) != got {
				t.Fatalf("IsDuckingOrTransitioning() = %v, want %v; package wrapper agrees: %v", got, tc.want, IsDuckingOrTransitioning(player) == got)
			}
		})
	}
}
