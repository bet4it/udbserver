#include <unicorn/unicorn.h>
#include "udbserver.h"

int ADDRESS = 0x1000;
const unsigned char ARM_CODE[4] =  {0x17, 0x00, 0x40, 0xe2}; // sub r0, #23

void empty_hook(void* handle, uint64_t _address, uint32_t _size) {}

int main()
{
	uc_engine *uc;
	uc_hook trace1, trace2;
	uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
	uc_mem_map(uc, ADDRESS, 0x400, UC_PROT_ALL);
	uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE));
	uc_hook_add(uc, &trace1, UC_HOOK_CODE, empty_hook, NULL, 1, 0);
	uc_hook_add(uc, &trace2, UC_HOOK_CODE, udbserver_hook, NULL, 0x1000, 0x1000);
	uc_emu_start(uc, 0x1000, 0x2000, 0, 0);
	return 0;
}
