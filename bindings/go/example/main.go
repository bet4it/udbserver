package main

import (
	"fmt"
	"unsafe"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	udbserver "sample.com/udbserver/go"
)

func run() error {
	code := []byte("\x17\x00\x40\xe2") // sub r0, #23

	mu, err := uc.NewUnicorn(uc.ARCH_ARM, uc.MODE_ARM)
	if err != nil {
		return err
	}
	if err := mu.MemMap(0x1000, 0x400); err != nil {
		return err
	}
	if err := mu.MemWrite(0x1000, code); err != nil {
		return err
	}
	if err := mu.RegWrite(uc.ARM_REG_PC, 0x1000); err != nil {
		return err
	}
	udbserver.Udbserver(uintptr(unsafe.Pointer(mu.Handle())))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}
