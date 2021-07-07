#include <unicorn/unicorn.h>
#include "udbserver.h"

int ADDRESS = 0x1000;
const unsigned char ARM_CODE[64] =  {0x0f, 0x00, 0xa0, 0xe1, 0x14, 0x00, 0x80, 0xe2, 0x00, 0x10, 0x90, 0xe5, 0x14, 0x10, 0x81, 0xe2, 0x00, 0x10, 0x80, 0xe5, 0xfb, 0xff, 0xff, 0xea};

void empty_hook() {}

int main()
{
	uc_engine *uc;
	uc_hook trace1, trace2, trace3;
	uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
	uc_mem_map(uc, ADDRESS, 0x400, UC_PROT_ALL);
	uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE));

	uc_hook_add(uc, &trace1, UC_HOOK_CODE, empty_hook, NULL, 1, 0);
    uc_hook_add(uc, &trace2, UC_HOOK_MEM_READ, empty_hook, NULL, 1, 0);
	uc_hook_add(uc, &trace3, UC_HOOK_CODE, udbserver_hook, NULL, 0x1000, 0x1000);

	uc_emu_start(uc, 0x1000, 0x2000, 0, 1000);
	return 0;
}
