package common

import st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"

func getInt(entity st.Entity, propName string) int {
	if entity == nil {
		return 0
	}

	val, ok := entity.PropertyValue(propName)
	if !ok {
		return 0
	}
	return val.Int()
}

func getUInt64(entity st.Entity, propName string) uint64 {
	if entity == nil {
		return 0
	}

	if entity.Property(propName) == nil {
		return 0
	}

	return entity.PropertyValueMust(propName).S2UInt64()
}

func getFloat(entity st.Entity, propName string) float32 {
	if entity == nil {
		return 0
	}

	val, ok := entity.PropertyValue(propName)
	if !ok {
		return 0
	}
	return val.Float()
}

func getString(entity st.Entity, propName string) string {
	if entity == nil {
		return ""
	}

	return entity.PropertyValueMust(propName).String()
}

func getBool(entity st.Entity, propName string) bool {
	if entity == nil {
		return false
	}

	val, ok := entity.PropertyValue(propName)
	if !ok {
		return false
	}

	return val.BoolVal()
}
