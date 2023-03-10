#include <stdio.h>
#include <unistd.h>

typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned char bool;

typedef size_t (*inst_proc)(u8 const*, size_t);

#define EXTEND_8TO16(n) ((n & 0xf0) ? (n | (u16)0xff00) : (u16)n)

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

#define INST_ARG_BUF_SIZE 24
struct r_to_rm_pair {
	char r[INST_ARG_BUF_SIZE];
	char rm[INST_ARG_BUF_SIZE];
};

static size_t render_r_to_rm(struct r_to_rm_pair *pair, u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	bool const wide = (stream[0] & 0x1) != 0;
	u8 const mod = (stream[1] >> 6);
	u8 r = (stream[1] >> 3) & 0x7;
	u8 rm = stream[1] & 0x07;

	if (wide) {
		r |= 0x08;
	}
	snprintf(&pair.r, INST_ARG_BUF_SIZE, "%s", reg_names[r]);

	switch (mod) {
		case 0:
			if (b == 6) {
				step += 2;
				if (len < step) {
					return 0;
				}
				/* direct address */
				snprintf(&pair.rm, INST_ARG_BUF_SIZE, "[%hu]", stream[2] | ((u16)stream[3] << 8));
			} else {
				snprintf(&pair.rm, INST_ARG_BUF_SIZE, "[%s]", eac_table[b]);
			}
			break;
		case 1:
			step += 1;
			if (len < step) {
				return 0;
			}
			snprintf(&pair.rm, INST_ARG_BUF_SIZE, "[%s + %hu]", eac_table[b], EXTEND_8TO16(stream[2]));
			break;
		case 2:
			step += 2;
			if (len < step) {
				return 0;
			}
			snprintf(&pair.rm, INST_ARG_BUF_SIZE, "[%s + %hu]", eac_table[b], stream[2] | ((u16)stream[3] << 8));
			break;
		case 3:
			if (wide) {
				rm |= 0x08;
			}
			snprintf(&pair.rm, INST_ARG_BUF_SIZE, "%s", reg_names[b]);
			break;
	}

	return step;
}

static size_t decode_r_to_rm(u8 const *stream, size_t len, char const *inst) {
	struct r_to_rm_pair pair;
	u8 step = render_r_to_rm(&pair, stream, len);

	if (step == 0) {
		return 0;
	}

	bool const reverse = (stream[0] & 0x2) != 0;

	if (reverse) {
		printf("%s %s, %s\n", inst, pair.r, pair.rm);
	} else {
		printf("%s %s, %s\n", inst, pair.rm, pair.r);
	}
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

static size_t dispatch(u8 const *stream, size_t len) {
	if (len == 0) {
		return 0;
	}

	switch (stream[0] >> 4) {
		case 0x0:
			switch (stream[0] & 0xf) {
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:
					return decode_r_to_rm(stream, len, "add");
				default:
					/* not implemented. */
					return 0;
			}
		case 0x1:
			/* not implemented. */
			return 0;
		case 0x2:
			switch (stream[0] & 0xf) {
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:
					return decode_r_to_rm(stream, len, "sub");
				default:
					/* not implemented. */
					return 0;
			}
		case 0x3:
			switch (stream[0] & 0xf) {
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:
					return decode_r_to_rm(stream, len, "cmp");
				default:
					/* not implemented. */
					return 0;
			}
		case 0x4:
			/* not implemented. */
			return 0;
		case 0x5:
			/* not implemented. */
			return 0;
		case 0x6:
			/* not implemented. */
			return 0;
		case 0x7:
			/* not implemented. */
			return 0;
		case 0x8:
			switch (stream[0] & 0xf) {
				case 0x88:
				case 0x89:
				case 0x8a:
				case 0x8b:
					return decode_r_to_rm(stream, len, "mov");
				default:
					/* not implemented. */
					return 0;
			}
		case 0x9:
			/* not implemented. */
			return 0;
		case 0xa:
			switch (stream[0] & 0xf) {
				case 0x0:
					return mov_mem2al(stream, len);
				case 0x1:
					return mov_mem2ax(stream, len);
				case 0x2:
					return mov_al2mem(stream, len);
				case 0x3:
					return mov_ax2mem(stream, len);
				default:
					/* not implemented. */
					return 0;
			}
			return 0;
		case 0xb:
			mov_immediate_to_reg(stream, len);
			return 0;
		case 0xc:
			switch (stream[0] & 0xf) {
				case 0x6:
					return mov_imm2narrow(stream, len);
				case 0x7:
					return mov_imm2wide(stream, len);
				default:
					/* not implemented. */
					return 0;
			}
		case 0xd:
			/* not implemented. */
			return 0;
		case 0xe:
			/* not implemented. */
			return 0;
		case 0xf:
			/* not implemented. */
			return 0;
	}
}

#define PROGRAM_BUF_SIZE 2048
int main(void) {
	u8 program[PROGRAM_BUF_SIZE];

	size_t program_len = read(0, program, PROGRAM_BUF_SIZE);
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
		size_t const step = dispatch(program + i, program_len - i);
		if (!step) {
			printf("unrecognized instruction at 0x%zx: 0x%02hhx\n", i, program[i]);
			return 0;
		}
		i += step;
	}

	return 0;
}
