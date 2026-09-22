package sendtables2

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

func TestUnsignedDecoderValueAndAlignment(t *testing.T) {
	for _, value := range []uint32{0, 1, 255, 256, 512, 1023, 1024, math.MaxUint32} {
		for _, offset := range []uint32{0, 3} {
			t.Run(fmt.Sprintf("%d/offset%d", value, offset), func(t *testing.T) {
				raw := binary.AppendUvarint(nil, uint64(value))
				raw = append(raw, 0xA5)
				packed := make([]byte, len(raw)+1)
				for i, b := range raw {
					bit := uint32(i*8) + offset
					packed[bit/8] |= b << (bit % 8)
					if bit%8 != 0 {
						packed[bit/8+1] |= b >> (8 - bit%8)
					}
				}
				r := newReader(packed)
				defer r.release()
				r.readBits(offset)
				decoded := unsignedDecoder(r)
				actual, ok := decoded.(uint64)
				if !ok || actual != uint64(value) {
					t.Fatalf("got %v (%T), want uint64(%d)", decoded, decoded, value)
				}
				if next := r.readByte(); next != 0xA5 {
					t.Fatalf("decoder consumed wrong number of bits: next byte %x", next)
				}
			})
		}
	}
}

var unsignedDecoderBenchmarkSink interface{}

func BenchmarkUnsignedDecoder(b *testing.B) {
	for _, value := range []uint32{512, 65536} {
		b.Run(fmt.Sprint(value), func(b *testing.B) {
			data := binary.AppendUvarint(nil, uint64(value))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := newReader(data)
				unsignedDecoderBenchmarkSink = unsignedDecoder(r)
				r.release()
			}
		})
	}
}

// Consumers can type-assert and mutate decoded vector slices. A repeated
// decode must not share the mutable backing array with an earlier result.
func TestVectorDecoderPreservesSliceOwnership(t *testing.T) {
	bits := int32(32)
	decoders := map[string]fieldDecoder{
		"vector": vectorFactory(3)(&field{bitCount: &bits}),
		"angle":  qangleFactory(&field{bitCount: &bits}),
		"normal": vectorNormalDecoder,
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			r := newReader(make([]byte, 16))
			first, ok := decode(r).([]float32)
			r.release()
			if !ok || len(first) != 3 {
				t.Fatalf("expected []float32 of length 3, got %v", first)
			}
			expected := append([]float32(nil), first...)
			first[0] = 123
			r = newReader(make([]byte, 16))
			defer r.release()
			second, ok := decode(r).([]float32)
			if !ok || len(second) != 3 {
				t.Fatalf("expected []float32 of length 3, got %v", second)
			}
			for i := range expected {
				if second[i] != expected[i] {
					t.Fatalf("previous result mutation affected next decode: %v", second)
				}
			}
		})
	}
}
