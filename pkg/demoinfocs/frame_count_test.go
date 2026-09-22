package demoinfocs

import (
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/common"
	"testing"
)

func TestFrameCount(t *testing.T) {
	var p Parser = &parser{}
	if p.FrameCount() != -1 {
		t.Fatal("total must be unknown before header")
	}
	for _, count := range []int{-1, 0, 12345} {
		p = &parser{header: &common.DemoHeader{PlaybackFrames: count}}
		want := count
		if want <= 0 {
			want = -1
		}
		if p.FrameCount() != want {
			t.Fatalf("FrameCount()=%d, want %d", p.FrameCount(), want)
		}
	}
}
