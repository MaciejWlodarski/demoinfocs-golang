//go:build !debugdemoinfocs
// +build !debugdemoinfocs

// This file is just a bunch of NOPs for the release build, see debug_on.go for debugging stuff

package demoinfocs

import (
	msg "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/msgs2"
	st "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/sendtables"
)

func debugGameEvent(descriptor *msg.CSVCMsg_GameEventListDescriptorT, ge *msg.CSVCMsg_GameEvent) {
	// NOP
}

func debugIngameTick(tickNr int) {
	// NOP
}

func debugAllServerClasses(classes st.ServerClasses) {
	// NOP
}
