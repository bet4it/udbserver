package unicorn

import (
	"unsafe"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

/*
#cgo CFLAGS: -O3 -Wall -Werror -I../../../include
#cgo LDFLAGS: -L../../../target/release -ludbserver
#cgo linux LDFLAGS: -L../../../target/release -ludbserver -lrt
#include "udbserver.h"
*/
import "C"

func Udbserver(mu uc.Unicorn, port uint16, start_addr uint64) error {
	C.udbserver(unsafe.Pointer(mu.Handle()), C.ushort(port), C.ulong(start_addr))
	return nil
}
