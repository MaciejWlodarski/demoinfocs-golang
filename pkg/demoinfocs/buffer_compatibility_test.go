package demoinfocs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/golang/snappy"
	bit "github.com/markus-wa/demoinfocs-golang/v4/internal/bitread"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/msgs2"
	dispatch "github.com/markus-wa/godispatch"
	"google.golang.org/protobuf/proto"
)

// Queued protobuf messages must retain their bytes after input buffers are reused.
func TestFramePayloadBufferOwnership(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			first := &msgs2.CDemoPacket{Data: bytes.Repeat([]byte{0x53}, 4096)}
			second := &msgs2.CDemoPacket{Data: bytes.Repeat([]byte{0x24}, 4096)}
			raw1, _ := proto.Marshal(first)
			raw2, _ := proto.Marshal(second)
			if compressed {
				raw1 = snappy.Encode(nil, raw1)
				raw2 = snappy.Encode(nil, raw2)
			}
			p := &parser{bitReader: bit.NewSmallBitReader(bytes.NewReader(append(raw1, raw2...)))}
			defer p.bitReader.Pool()
			payload, bp := p.readFramePayload(len(raw1), compressed)
			retained := new(msgs2.CDemoPacket)
			if err := proto.Unmarshal(payload, retained); err != nil {
				t.Fatal(err)
			}
			putMsgBuf(bp)
			payload, bp = p.readFramePayload(len(raw2), compressed)
			defer putMsgBuf(bp)
			actual := new(msgs2.CDemoPacket)
			if err := proto.Unmarshal(payload, actual); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(retained, first) || !proto.Equal(actual, second) {
				t.Fatal("buffer reuse changed a decoded message")
			}
		})
	}
}

func TestFatalErrorStopsQueuedHandlers(t *testing.T) {
	p := &parser{msgDispatcher: new(dispatch.Dispatcher), eventDispatcher: new(dispatch.Dispatcher)}
	first := errors.New("first fatal error")
	messages, events := 0, 0
	p.msgDispatcher.RegisterHandler(func(v int32) { messages++; p.setError(first) })
	p.eventDispatcher.RegisterHandler(func(string) { events++ })
	queue := make(chan any, 2)
	p.msgDispatcher.AddQueues(queue)
	defer p.msgDispatcher.RemoveQueues(queue)
	queue <- int32(1)
	queue <- int32(2)
	p.msgDispatcher.SyncAllQueues()
	p.eventDispatcher.Dispatch("backlog")
	p.setError(errors.New("later error"))
	if messages != 1 || events != 0 {
		t.Fatalf("handlers after fatal error: messages=%d events=%d", messages, events)
	}
	if p.error() != first {
		t.Fatalf("first error overwritten: %v", p.error())
	}
}

func TestFramePayloadRejectsTruncatedInput(t *testing.T) {
	p := &parser{bitReader: bit.NewSmallBitReader(bytes.NewReader([]byte{1, 2}))}
	defer p.bitReader.Pool()
	defer func() {
		if got := recover(); got != io.ErrUnexpectedEOF {
			t.Fatalf("got %v, want unexpected EOF", got)
		}
	}()
	p.readFramePayload(16, false)
}
