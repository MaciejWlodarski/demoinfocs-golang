package common

import (
	"testing"

	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

type silencedTestEntity struct {
	st.Entity
	property st.Property
}

func (e silencedTestEntity) Property(name string) st.Property {
	if name != "m_bSilencerOn" {
		panic("unexpected property: " + name)
	}
	return e.property
}

type silencedTestProperty struct {
	st.Property
	value bool
}

func (p silencedTestProperty) Value() st.PropertyValue {
	return st.PropertyValue{Any: p.value, S2: true}
}

func TestEquipmentSilenced(t *testing.T) {
	for _, test := range []struct {
		name   string
		entity st.Entity
		want   bool
	}{
		{name: "no entity"},
		{name: "class without silencer", entity: silencedTestEntity{}},
		{name: "silencer off", entity: silencedTestEntity{property: silencedTestProperty{value: false}}},
		{name: "silencer on", entity: silencedTestEntity{property: silencedTestProperty{value: true}}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			weapon := &Equipment{Entity: test.entity}
			if got := weapon.Silenced(); got != test.want {
				t.Fatalf("Silenced() = %t, want %t", got, test.want)
			}
		})
	}
}
