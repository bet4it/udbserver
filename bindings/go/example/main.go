package main

import (
	"fmt"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	udbserver "sample.com/udbserver/go/udbserver"
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

	mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {}, 1, 0)
	mu.HookAdd(uc.HOOK_CODE, udbserver.UdbserverHook, 0x1000, 0x1000)

	if err := mu.Start(0x1000, 0x2000); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}
