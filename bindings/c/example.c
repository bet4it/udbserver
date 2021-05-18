#include <unicorn/unicorn.h>
#include "udbserver.h"

int ADDRESS = 0x1000;
const unsigned char ARM_CODE[4] =  {0x17, 0x00, 0x40, 0xe2}; // sub r0, #23

int main()
{
	uc_engine *uc;
	uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
	uc_mem_map(uc, ADDRESS, 0x400, UC_PROT_ALL);
	uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE));
	uc_reg_write(uc, UC_ARM_REG_PC, &ADDRESS);
	uc_reg_read(uc, UC_ARM_REG_PC, &ADDRESS);
	return udbserver(uc);
}
