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

func Udbserver(mu uc.Unicorn) error {
	C.udbserver(unsafe.Pointer(mu.Handle()))
	return nil
}
