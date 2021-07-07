package main

import (
	"fmt"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	udbserver "sample.com/udbserver/go/udbserver"
)

func run() error {
	code := []byte("\x0f\x00\xa0\xe1\x14\x00\x80\xe2\x00\x10\x90\xe5\x14\x10\x81\xe2\x00\x10\x80\xe5\xfb\xff\xff\xea")

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

	mu.HookAdd(uc.HOOK_CODE, func(_mu uc.Unicorn, _addr uint64, _size uint32) {}, 1, 0)
	mu.HookAdd(uc.HOOK_MEM_READ, func(_mu uc.Unicorn, _type int, _addr uint64, _size int, _value int64) {}, 1, 0)
	mu.HookAdd(uc.HOOK_CODE, udbserver.UdbserverHook, 0x1000, 0x1000)

	if err := mu.StartWithOptions(0x1000, 0x2000, &uc.UcOptions{0, 1000}); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}
