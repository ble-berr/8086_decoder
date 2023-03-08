#include <stdio.h>
#include <unistd.h>

typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned char bool;

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

#define MOV_ARG_BUF_SIZE 24
static size_t mov_r_to_rm(u8 const *stream, size_t len) {
	if (len < 2) {
		return 0;
	}

	bool const from_rm = !!(stream[0] & 0x2);
	bool const wide = !!(stream[0] & 0x1);
	u8 const mod = (stream[1] >> 6);
	u8 a = (stream[1] & 0x38) >> 3;
	u8 b = (stream[1] & 0x07);
	u8 to[MOV_ARG_BUF_SIZE] = {};
	u8 from[MOV_ARG_BUF_SIZE] = {};
	u8 consumed = 2;

	if (wide) {
		a |= 0x08;
	}
	snprintf(from_rm?to:from, MOV_ARG_BUF_SIZE, "%s", reg_names[a]);

	switch (mod) {
		case 3:
			if (wide) {
				b |= 0x08;
			}
			snprintf(from_rm?from:to, MOV_ARG_BUF_SIZE, "%s", reg_names[b]);
			break;
		case 2:
			snprintf(from_rm?from:to, MOV_ARG_BUF_SIZE, "[%s + %hu]", eac_table[b], stream[2] | ((u16)stream[3] << 8));
			consumed += 2;
			break;
		case 1:
			snprintf(from_rm?from:to, MOV_ARG_BUF_SIZE, "[%s + %hu]", eac_table[b], EXTEND_8TO16(stream[2]));
			consumed += 1;
			break;
		case 0:
			if (b == 6) {
				/* direct address */
				snprintf(from_rm?from:to, MOV_ARG_BUF_SIZE, "[%hu]", stream[2] | ((u16)stream[3] << 8));
				consumed += 2;
			} else {
				snprintf(from_rm?from:to, MOV_ARG_BUF_SIZE, "[%s]", eac_table[b]);
			}
			break;
	}

	printf("mov %s, %s\n", to, from);
	return consumed;
}

static size_t mov_immediate_to_reg(u8 const *stream, size_t len) {
	if (len < 2) {
		return 0;
	}
	bool const wide = !!(stream[0] & 0x08);
	bool reg = stream[0] & 0x07;
	u16 immediate = stream[1];
	u8 consumed = 2;

	if (wide) {
		reg |= 0x08;
		immediate |= stream[2] << 8;
		consumed += 1;
	}

	printf("mov %s, %hu\n", reg_names[reg], immediate);
	return consumed;
}

static size_t mov_imm2narrow(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	u8 mod = (stream[1] & 0xc0) >> 6;
	u8 b = stream[1] & 0x07;

	switch (mod) {
		case 0:
			{
				if (b == 6) {
					/* direct address */
					printf("mov [%hu], byte %hu\n", stream[2] | ((u16)stream[3] << 8), EXTEND_8TO16(stream[4]));
					return 5;
				} else {
					printf("mov [%s], byte %hu\n", eac_table[b], EXTEND_8TO16(stream[2]));
					return 3;
				}
			}
		case 1:
			printf("mov [%s + %hu], byte %hu\n", eac_table[b], EXTEND_8TO16(stream[2]), EXTEND_8TO16(stream[3]));
			return 4;
		case 2:
			printf("mov [%s + %hu], byte %hu\n", eac_table[b], stream[2] | ((u16)stream[3] << 8), EXTEND_8TO16(stream[4]));
			return 5;
		case 3:
			printf("mov %s, byte %hu\n", reg_names[b], EXTEND_8TO16(stream[2]));
			return 3;
	}

	return 2;
}


static size_t mov_imm2wide(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	u8 mod = (stream[1] & 0xc0) >> 6;
	u8 b = stream[1] & 0x07;

	switch (mod) {
		case 0:
			{
				if (b == 6) {
					/* direct address */
					printf("mov [%hu], word %hu\n", stream[2] | ((u16)stream[3] << 8), stream[4] | ((u16)stream[5] << 8));
					return 6;
				} else {
					printf("mov [%s], word %hu\n", eac_table[b], stream[2] | ((u16)stream[3] << 8));
					return 4;
				}
			}
		case 1:
			printf("mov [%s + %hu], word %hu\n", eac_table[b], EXTEND_8TO16(stream[2]), stream[3] | ((u16)stream[4] << 8));
			return 5;
		case 2:
			printf("mov [%s + %hu], word %hu\n", eac_table[b], stream[2] | ((u16)stream[3] << 8), stream[4] | ((u16)stream[5] << 8));
			return 6;
		case 3:
			b |= 0x8;
			printf("mov %s, word %hu\n", reg_names[b], stream[2] | ((u16)stream[3] << 8));
			return 4;
	}

	return 2;
}

static size_t mov_mem2al(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov al, [%hu]\n", stream[1] | ((u16)stream[2] << 8));
	return 3;
}

static size_t mov_mem2ax(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov ax, [%hu]\n", stream[1] | ((u16)stream[2] << 8));
	return 3;
}

static size_t mov_al2mem(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], al\n", stream[1] | ((u16)stream[2] << 8));
	return 3;
}

static size_t mov_ax2mem(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], ax\n", stream[1] | ((u16)stream[2] << 8));
	return 3;
}

#define PROGRAM_BUF_SIZE 2048
int main(void) {
	u8 program[PROGRAM_BUF_SIZE];

	instruction_table[0x88] = &mov_r_to_rm;
	instruction_table[0x89] = &mov_r_to_rm;
	instruction_table[0x8a] = &mov_r_to_rm;
	instruction_table[0x8b] = &mov_r_to_rm;

	instruction_table[0xa0] = &mov_mem2al;
	instruction_table[0xa1] = &mov_mem2ax;
	instruction_table[0xa2] = &mov_al2mem;
	instruction_table[0xa3] = &mov_ax2mem;

	instruction_table[0xb0] = &mov_immediate_to_reg;
	instruction_table[0xb1] = &mov_immediate_to_reg;
	instruction_table[0xb2] = &mov_immediate_to_reg;
	instruction_table[0xb3] = &mov_immediate_to_reg;
	instruction_table[0xb4] = &mov_immediate_to_reg;
	instruction_table[0xb5] = &mov_immediate_to_reg;
	instruction_table[0xb6] = &mov_immediate_to_reg;
	instruction_table[0xb7] = &mov_immediate_to_reg;
	instruction_table[0xb8] = &mov_immediate_to_reg;
	instruction_table[0xb9] = &mov_immediate_to_reg;
	instruction_table[0xba] = &mov_immediate_to_reg;
	instruction_table[0xbb] = &mov_immediate_to_reg;
	instruction_table[0xbc] = &mov_immediate_to_reg;
	instruction_table[0xbd] = &mov_immediate_to_reg;
	instruction_table[0xbe] = &mov_immediate_to_reg;
	instruction_table[0xbf] = &mov_immediate_to_reg;

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
		inst_proc const proc = instruction_table[program[i]];
		size_t const consumed = proc ? proc(program + i, program_len - i) : 0;
		if (!consumed) {
			printf("unrecognized instruction at 0x%zx: 0x%02hhx\n", i, program[i]);
			return 0;
		}
		i += consumed;
	}

	return 0;
}
