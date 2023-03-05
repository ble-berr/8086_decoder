#include <stdio.h>
#include <unistd.h>

typedef unsigned short u16;
typedef unsigned char u8;

typedef size_t (*inst_proc)(u8 const*, size_t);

#define EXTEND_8TO16(n) ((n & 0xf0) ? (n | (u16)0xff00) : (u16)n)

static inst_proc instruction_table[256];

enum e_reg {
	REG_AL,
	REG_CL,
	REG_DL,
	REG_BL,
	REG_AH,
	REG_CH,
	REG_DH,
	REG_BH,
	REG_AX,
	REG_CX,
	REG_DX,
	REG_BX,
	REG_SP,
	REG_BP,
	REG_SI,
	REG_DI,
};

char const *reg_names[16] = {
	"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
	"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
};

static char const *eac_table[8] = {
	"bx + si",
	"bx + di",
	"bp + si",
	"bp + di",
	"si",
	"di",
	"bp",
	"bx",
};

static size_t mov_narrow_to(u8 const *stream, size_t len) {
	if (!len) {
		return 0;
	}

	u8 byte_2 = stream[0];
	u8 mod = (byte_2 & 0xc0) >> 6;
	u8 a = (byte_2 & 0x38) >> 3;
	u8 b = (byte_2 & 0x07);

	switch (mod) {
		case 0:
			if (b == 6) {
				/* direct address */
				printf("mov %s, [%hu]\n", reg_names[a], stream[1] | ((u16)stream[2] << 8));
				return 3;
			} else {
				printf("mov %s, [%s]\n", reg_names[a], eac_table[b]);
				return 1;
			}
		case 1:
			printf("mov %s, [%s + %hhu]\n", reg_names[a], eac_table[b], stream[1]);
			return 2;
		case 2:
			printf("mov %s, [%s + %hu]\n", reg_names[a], eac_table[b], stream[1] | ((u16)stream[2] << 8));
			return 3;
		case 3:
			printf("mov %s, %s\n", reg_names[a], reg_names[b]);
			return 1;
	}

	return 1;
}

static size_t mov_narrow_from(u8 const *stream, size_t len) {
	if (!len) {
		return 0;
	}

	u8 byte_2 = stream[0];
	u8 mod = (byte_2 & 0xc0) >> 6;
	u8 a = (byte_2 & 0x38) >> 3;
	u8 b = (byte_2 & 0x07);

	switch (mod) {
		case 0:
			if (b == 6) {
				/* direct address */
				printf("mov [%hu], %s\n", stream[1] | ((u16)stream[2] << 8), reg_names[a]);
				return 3;
			} else {
				printf("mov [%s], %s\n", eac_table[b], reg_names[a]);
				return 1;
			}
		case 1:
			printf("mov [%s + %hhu], %s\n", eac_table[b], stream[1], reg_names[a]);
			return 2;
		case 2:
			printf("mov [%s + %hu], %s\n", eac_table[b], stream[1] | ((u16)stream[2] << 8), reg_names[a]);
			return 3;
		case 3:
			printf("mov %s, %s\n", reg_names[b], reg_names[a]);
			return 1;
	}

	return 1;
}

static size_t mov_wide_to(u8 const *stream, size_t len) {
	if (!len) {
		return 0;
	}

	u8 byte_2 = stream[0];
	u8 mod = (byte_2 & 0xc0) >> 6;
	u8 a = ((byte_2 & 0x38) >> 3) | 0x8;
	u8 b = (byte_2 & 0x07);

	switch (mod) {
		case 0:
			if (b == 6) {
				/* direct address */
				printf("mov %s, [%hu]\n", reg_names[a], stream[1] | ((u16)stream[2] << 8));
				return 3;
			} else {
				printf("mov %s, [%s]\n", reg_names[a], eac_table[b]);
				return 1;
			}
		case 1:
			printf("mov %s, [%s + %hu]\n", reg_names[a], eac_table[b], EXTEND_8TO16(stream[1]));
			return 2;
		case 2:
			printf("mov %s, [%s + %hu]\n", reg_names[a], eac_table[b], stream[1] | ((u16)stream[2] << 8));
			return 3;
		case 3:
			b |= 0x8;
			printf("mov %s, %s\n", reg_names[a], reg_names[b]);
			return 1;
	}

	return 1;
}

static size_t mov_wide_from(u8 const *stream, size_t len) {
	if (!len) {
		return 0;
	}

	u8 byte_2 = stream[0];
	u8 mod = (byte_2 & 0xc0) >> 6;
	u8 a = ((byte_2 & 0x38) >> 3) | 0x8;
	u8 b = (byte_2 & 0x07);

	switch (mod) {
		case 0:
			if (b == 6) {
				/* direct address */
				printf("mov [%hu], %s\n", stream[1] | ((u16)stream[2] << 8), reg_names[a]);
				return 3;
			} else {
				printf("mov [%s], %s\n", eac_table[b], reg_names[a]);
				return 1;
			}
		case 1:
			printf("mov [%s + %hu], %s\n", eac_table[b], EXTEND_8TO16(stream[1]), reg_names[a]);
			return 2;
		case 2:
			printf("mov [%s + %hu], %s\n", eac_table[b], stream[1] | ((u16)stream[2] << 8), reg_names[a]);
			return 3;
		case 3:
			b |= 0x8;
			printf("mov %s, %s\n", reg_names[b], reg_names[a]);
			return 1;
	}

	return 1;
}

/* TODO(benjamin): check/assert length. */
#define PRINT_IMM2NARROW(reg) printf("mov %s, %hhu\n", reg_names[reg], stream[0])
#define FUNC_IMM2NARROW(name, reg) static size_t name(u8 const *stream, size_t len) { PRINT_IMM2NARROW(reg); return 1; }
FUNC_IMM2NARROW(mov_imm2al, REG_AL)
FUNC_IMM2NARROW(mov_imm2cl, REG_CL)
FUNC_IMM2NARROW(mov_imm2dl, REG_DL)
FUNC_IMM2NARROW(mov_imm2bl, REG_BL)
FUNC_IMM2NARROW(mov_imm2ah, REG_AH)
FUNC_IMM2NARROW(mov_imm2ch, REG_CH)
FUNC_IMM2NARROW(mov_imm2dh, REG_DH)
FUNC_IMM2NARROW(mov_imm2bh, REG_BH)

/* TODO(benjamin): check/assert length. */
#define PRINT_IMM2WIDE(reg) printf("mov %s, %hu\n", reg_names[reg], stream[0] | ((u16)stream[1] << 8))
#define FUNC_IMM2WIDE(name, reg) static size_t name(u8 const *stream, size_t len) { PRINT_IMM2WIDE(reg); return 2; }
FUNC_IMM2WIDE(mov_imm2ax, REG_AX)
FUNC_IMM2WIDE(mov_imm2cx, REG_CX)
FUNC_IMM2WIDE(mov_imm2dx, REG_DX)
FUNC_IMM2WIDE(mov_imm2bx, REG_BX)
FUNC_IMM2WIDE(mov_imm2sp, REG_SP)
FUNC_IMM2WIDE(mov_imm2bp, REG_BP)
FUNC_IMM2WIDE(mov_imm2si, REG_SI)
FUNC_IMM2WIDE(mov_imm2di, REG_DI)

static size_t mov_imm2narrow(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	u8 mod = (stream[0] & 0xc0) >> 6;
	u8 b = stream[0] & 0x07;

	switch (mod) {
		case 0:
			{
				if (b == 6) {
					/* direct address */
					printf("mov [%hu], byte %hu\n", stream[1] | ((u16)stream[2] << 8), EXTEND_8TO16(stream[3]));
					return 4;
				} else {
					printf("mov [%s], byte %hu\n", eac_table[b], EXTEND_8TO16(stream[1]));
					return 2;
				}
			}
		case 1:
			printf("mov [%s + %hu], byte %hu\n", eac_table[b], EXTEND_8TO16(stream[1]), EXTEND_8TO16(stream[2]));
			return 3;
		case 2:
			printf("mov [%s + %hu], byte %hu\n", eac_table[b], stream[1] | ((u16)stream[2] << 8), EXTEND_8TO16(stream[3]));
			return 4;
		case 3:
			printf("mov %s, byte %hu\n", reg_names[b], EXTEND_8TO16(stream[1]));
			return 1;
	}

	return 1;
}


static size_t mov_imm2wide(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	u8 mod = (stream[0] & 0xc0) >> 6;
	u8 b = stream[0] & 0x07;

	switch (mod) {
		case 0:
			{
				if (b == 6) {
					/* direct address */
					printf("mov [%hu], word %hu\n", stream[1] | ((u16)stream[2] << 8), stream[3] | ((u16)stream[4] << 8));
					return 5;
				} else {
					printf("mov [%s], word %hu\n", eac_table[b], stream[1] | ((u16)stream[2] << 8));
					return 3;
				}
			}
		case 1:
			printf("mov [%s + %hu], word %hu\n", eac_table[b], EXTEND_8TO16(stream[1]), stream[2] | ((u16)stream[3] << 8));
			return 4;
		case 2:
			printf("mov [%s + %hu], word %hu\n", eac_table[b], stream[1] | ((u16)stream[2] << 8), stream[3] | ((u16)stream[4] << 8));
			return 5;
		case 3:
			b |= 0x8;
			printf("mov %s, word %hu\n", reg_names[b], stream[1] | ((u16)stream[2] << 8));
			return 1;
	}

	return 1;
}

static size_t mov_mem2al(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov al, [%hu]\n", stream[0] | ((u16)stream[1] << 8));
	return 2;
}

static size_t mov_mem2ax(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov ax, [%hu]\n", stream[0] | ((u16)stream[1] << 8));
	return 2;
}

static size_t mov_al2mem(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], al\n", stream[0] | ((u16)stream[1] << 8));
	return 2;
}

static size_t mov_ax2mem(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], ax\n", stream[0] | ((u16)stream[1] << 8));
	return 2;
}

#define PROGRAM_BUF_SIZE 2048
int main(void) {
	u8 program[PROGRAM_BUF_SIZE];

	instruction_table[0x88] = &mov_narrow_from;
	instruction_table[0x89] = &mov_wide_from;
	instruction_table[0x8a] = &mov_narrow_to;
	instruction_table[0x8b] = &mov_wide_to;

	instruction_table[0xa0] = &mov_mem2al;
	instruction_table[0xa1] = &mov_mem2ax;
	instruction_table[0xa2] = &mov_al2mem;
	instruction_table[0xa3] = &mov_ax2mem;

	instruction_table[0xb0] = &mov_imm2al;
	instruction_table[0xb1] = &mov_imm2cl;
	instruction_table[0xb2] = &mov_imm2dl;
	instruction_table[0xb3] = &mov_imm2bl;
	instruction_table[0xb4] = &mov_imm2ah;
	instruction_table[0xb5] = &mov_imm2ch;
	instruction_table[0xb6] = &mov_imm2dh;
	instruction_table[0xb7] = &mov_imm2bh;
	instruction_table[0xb8] = &mov_imm2ax;
	instruction_table[0xb9] = &mov_imm2cx;
	instruction_table[0xba] = &mov_imm2dx;
	instruction_table[0xbb] = &mov_imm2bx;
	instruction_table[0xbc] = &mov_imm2sp;
	instruction_table[0xbd] = &mov_imm2bp;
	instruction_table[0xbe] = &mov_imm2si;
	instruction_table[0xbf] = &mov_imm2di;

	instruction_table[0xc6] = &mov_imm2narrow;
	instruction_table[0xc7] = &mov_imm2wide;

	size_t program_len = read(0, program, 512);
	if (program_len == -1) {
		return 1;
	}
	if (program_len == PROGRAM_BUF_SIZE) {
		switch (read(0, program, 1)) {
			case -1:
				return 2;
			case 1:
				dprintf(2, "undersized program buffer\n");
				return 3;
			case 0:
				break;
			default:
				/* unreachable */
				return 4;
		}
	}

	printf("bits 16\n");
	for (size_t i = 0; i < program_len;) {
		inst_proc proc = instruction_table[program[i]];
		if (proc) {
			i += 1;
			i += proc(program + i, program_len - i);
		} else {
			printf("unrecognized instruction: 0x%02hhx\n", program[i]);
			i += 1;
		}
	}

	return 0;
}
