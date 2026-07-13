// Package main is a size/interop experiment, not production Worker code.
package main

import "unsafe"

const (
	resultNeedMore = 0
	resultInvalid  = 1 << 31
)

// parseVLESS returns the fixed-subset header length, zero for incomplete input,
// or the high bit for invalid input. It deliberately excludes stream bridging,
// authentication hashing, address formatting, and JavaScript memory copies, so
// its Wasm size is a favorable lower bound rather than a production estimate.
//
//export parseVLESS
func parseVLESS(pointer *byte, length uint32) uint32 {
	if pointer == nil || length == 0 {
		return resultNeedMore
	}
	input := unsafe.Slice(pointer, int(length))
	if input[0] != 0 {
		return resultInvalid
	}
	if len(input) < 18 {
		return resultNeedMore
	}
	if input[17] != 0 {
		return resultInvalid
	}
	if len(input) < 22 {
		return resultNeedMore
	}
	if input[18] != 1 || input[19] == 0 && input[20] == 0 {
		return resultInvalid
	}
	offset := 22
	switch input[21] {
	case 1:
		offset += 4
	case 2:
		if len(input) < offset+1 {
			return resultNeedMore
		}
		domainLength := int(input[offset])
		if domainLength == 0 {
			return resultInvalid
		}
		offset += 1 + domainLength
	case 3:
		offset += 16
	default:
		return resultInvalid
	}
	if len(input) < offset {
		return resultNeedMore
	}
	return uint32(offset)
}

func main() {}
