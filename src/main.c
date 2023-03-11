#include <stdio.h>
#include <unistd.h>

typedef unsigned short u16;
typedef signed short s16;
typedef unsigned char u8;
typedef signed char s8;
typedef unsigned char bool;

typedef size_t (*inst_proc)(u8 const*, size_t);

#define SIGN_EXTEND(n) ((n & (u8)0x80) ? (n | (u16)0xff00) : (u16)n)
#define DATA16(data_lo, data_hi) (data_lo | (data_hi << (u16)8))

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
	snprintf(pair->r, INST_ARG_BUF_SIZE, "%s", reg_names[r]);

	switch (mod) {
		case 0:
			if (rm == 6) {
				step += 2;
				if (len < step) {
					return 0;
				}
				/* direct address */
				snprintf(pair->rm, INST_ARG_BUF_SIZE, "[%hu]", DATA16(stream[2], stream[3]));
			} else {
				snprintf(pair->rm, INST_ARG_BUF_SIZE, "[%s]", eac_table[rm]);
			}
			break;
		case 1:
			step += 1;
			if (len < step) {
				return 0;
			}
			/* TODO(benjamin): standard compliant signed conversion. */
			snprintf(pair->rm, INST_ARG_BUF_SIZE, "[%s + %hi]", eac_table[rm], (s16)SIGN_EXTEND(stream[2]));
			break;
		case 2:
			step += 2;
			if (len < step) {
				return 0;
			}
			/* TODO(benjamin): standard compliant signed conversion. */
			snprintf(pair->rm, INST_ARG_BUF_SIZE, "[%s + %hi]", eac_table[rm], (s16)DATA16(stream[2], stream[3]));
			break;
		case 3:
			if (wide) {
				rm |= 0x08;
			}
			snprintf(pair->rm, INST_ARG_BUF_SIZE, "%s", reg_names[rm]);
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

	return step;
}

static size_t mov_immediate_to_reg(u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}
	bool const wide = !!(stream[0] & 0x08);
	bool reg = stream[0] & 0x07;
	u16 immediate;

	if (wide) {
		step += 1;
		if (len < step) {
			return 0;
		}
		reg |= 0x08;
		immediate = DATA16(stream[1], stream[2]);
	} else {
		immediate = SIGN_EXTEND(stream[1]);
	}

	printf("mov %s, %hu\n", reg_names[reg], immediate);
	return step;
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
					printf("mov [%hu], byte %hu\n", DATA16(stream[2], stream[3]), SIGN_EXTEND(stream[4]));
					return 5;
				} else {
					printf("mov [%s], byte %hu\n", eac_table[b], SIGN_EXTEND(stream[2]));
					return 3;
				}
			}
		case 1:
			printf("mov [%s + %hu], byte %hu\n", eac_table[b], SIGN_EXTEND(stream[2]), SIGN_EXTEND(stream[3]));
			return 4;
		case 2:
			printf("mov [%s + %hu], byte %hu\n", eac_table[b], DATA16(stream[2], stream[3]), SIGN_EXTEND(stream[4]));
			return 5;
		case 3:
			printf("mov %s, byte %hu\n", reg_names[b], SIGN_EXTEND(stream[2]));
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
			if (b == 6) {
				/* direct address */
				printf("mov [%hu], word %hu\n", DATA16(stream[2], stream[3]), DATA16(stream[4], stream[5]));
				return 6;
			} else {
				printf("mov [%s], word %hu\n", eac_table[b], DATA16(stream[2], stream[3]));
				return 4;
			}
		case 1:
			printf("mov [%s + %hu], word %hu\n", eac_table[b], SIGN_EXTEND(stream[2]), DATA16(stream[3], stream[4]));
			return 5;
		case 2:
			printf("mov [%s + %hu], word %hu\n", eac_table[b], DATA16(stream[2], stream[3]), DATA16(stream[4], stream[5]));
			return 6;
		case 3:
			b |= 0x8;
			printf("mov %s, word %hu\n", reg_names[b], DATA16(stream[2], stream[3]));
			return 4;
	}

	return 2;
}

static size_t op_acc_immediate(u8 const *stream, size_t len, char const *mnemonic) {
	bool const wide = (stream[0] & 0x1u) != 0;
	u8 const step = 2 + wide;
	if (len < step) {
		return 0;
	}

	if (wide) {
		printf("%s ax, word %hu\n", mnemonic, DATA16(stream[1], stream[2]));
	} else {
		/* TODO(benjamin): standard compliant signed conversion. */
		printf("%s al, byte %hhi\n", mnemonic, (s8)stream[1]);
	}
	return step;
}

char const *arithmetic_mnemonics[8] = {
	"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"
};

static size_t op_rm_immediate(u8 const *stream, size_t len) {
	if (len == 0) {
		return 0;
	}

	bool const sign_extend = (stream[0] & 0x2u) != 0;
	bool const wide = (stream[0] & 0x1u) != 0;
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	u8 const mod = stream[1] >> 6;
	u8 const op = stream[1] >> 3 & 0x7;
	u8 dest = stream[1] & 0x7;

	char dest_str[INST_ARG_BUF_SIZE] = {};
	switch (mod) {
		case 0:
			if (dest == 6) {
				/* direct address */
				step += 2;
				if (len < step) {
					return 0;
				}
				snprintf(dest_str, INST_ARG_BUF_SIZE, "[%hu]", DATA16(stream[2], stream[3]));
			} else {
				snprintf(dest_str, INST_ARG_BUF_SIZE, "[%s]", eac_table[dest]);
			}
			break;
		case 1:
			step += 1;
			if (len < step) {
				return 0;
			}
			snprintf(dest_str, INST_ARG_BUF_SIZE, "[%s + %hu]", eac_table[dest], SIGN_EXTEND(stream[2]));
			break;
		case 2:
			step += 2;
			if (len < step) {
				return 0;
			}
			snprintf(dest_str, INST_ARG_BUF_SIZE, "[%s + %hu]", eac_table[dest], DATA16(stream[2], stream[3]));
			break;
		case 3:
			if (wide) {
				dest |= 0x08;
			}
			snprintf(dest_str, INST_ARG_BUF_SIZE, "%s", reg_names[dest]);
			break;
	}

	u16 immediate;
	if (sign_extend) {
		step += 1;
		if (len < step) {
			return 0;
		}
		immediate = SIGN_EXTEND(stream[step - 1]);
	} else if (wide) {
		step += 2;
		if (len < step) {
			return 0;
		}
		immediate = DATA16(stream[step - 2], stream[step - 1]);
	} else {
		step += 1;
		if (len < step) {
			return 0;
		}
		immediate = stream[step - 1];
	}

	printf("%s %s %s, %hu\n", arithmetic_mnemonics[op], wide?"word":"byte", dest_str, immediate);
	return step;
}

static size_t mov_mem2al(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov al, [%hu]\n", DATA16(stream[1], stream[2]));
	return 3;
}

static size_t mov_mem2ax(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov ax, [%hu]\n", DATA16(stream[1], stream[2]));
	return 3;
}

static size_t mov_al2mem(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], al\n", DATA16(stream[1], stream[2]));
	return 3;
}

static size_t mov_ax2mem(u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], ax\n", DATA16(stream[1], stream[2]));
	return 3;
}

static char const *const conditional_jump_mnemonics[0x10] = {
	"jo",
	"jno",
	"jb",
	"jnb",
	"je",
	"jne",
	"jbe",
	"jnbe",
	"js",
	"jns",
	"jp",
	"jnp",
	"jl",
	"jnl",
	"jle",
	"jnle",
};

static size_t conditional_jump(u8 const *stream, size_t len) {
	if (len < 2) {
		return 0;
	}
	/* TODO(benjamin): standard compliant signed conversion. */
	/* TODO(benjamin): test and handle overflow */
	s8 const ip_inc_8 = stream[1] + (u8)2;
	printf("%s $%+hhi\n", conditional_jump_mnemonics[stream[0] & 0xf], ip_inc_8);
	return 2;
}

static char const *const extra_jump_mnemonics[0x4] = {
	"loopne",
	"loope",
	"loop",
	"jcxz",
};

static size_t extra_jump(u8 const *stream, size_t len) {
	if (len < 2) {
		return 0;
	}
	/* TODO(benjamin): standard compliant signed conversion. */
	/* TODO(benjamin): test and handle overflow */
	s8 const ip_inc_8 = stream[1] + (u8)2;
	printf("%s $%+hhi\n", extra_jump_mnemonics[stream[0] & 0x3], ip_inc_8);
	return 2;
}

static size_t dispatch(u8 const *stream, size_t len) {
	if (len == 0) {
		return 0;
	}

	switch (stream[0] >> 4) {
		case 0x0:
		case 0x1:
		case 0x2:
		case 0x3:
			switch (stream[0] & 7u) {
				case 0:
				case 1:
				case 2:
				case 3:
					return decode_r_to_rm(stream, len, arithmetic_mnemonics[(stream[0] & 070u) >> 3]);
				case 4:
				case 5:
					return op_acc_immediate(stream, len, arithmetic_mnemonics[(stream[0] & 070u) >> 3]);
				case 6:
				case 7:
					/* not implemented. */
					return 0;
				default:
					/* unreachable */
					return 0;
			}
		case 0x4:
			/* not implemented. */
			return 0;
		case 0x5:
			/* not implemented. */
			return 0;
		case 0x6:
			/* unused. */
			return 0;
		case 0x7:
			return conditional_jump(stream, len);
		case 0x8:
			switch (stream[0] & 0xf) {
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:
					return op_rm_immediate(stream, len);
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:
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
		case 0xb:
			return mov_immediate_to_reg(stream, len);
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
			switch (stream[0] & 0xf) {
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:
					return extra_jump(stream, len);
				default:
					/* not implemented. */
					return 0;
			}
		case 0xf:
			/* not implemented. */
			return 0;
		default: /* unreachable */
			return 0;
	}
}

#define PROGRAM_BUF_SIZE 2048
int main(void) {
	u8 program[PROGRAM_BUF_SIZE];

	size_t program_len = read(0, program, PROGRAM_BUF_SIZE);
	if (program_len == (size_t)-1) {
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
			printf("unrecognized instruction: program[0x%zx]: 0x%02hhx\n", i, program[i]);
			return 0;
		}
		/*
		dprintf(2, "opcode:");
		for (size_t j = 0; j < step; ++j) {
			dprintf(2, " 0x%02hhx", program[i + j]);
		}
		dprintf(2, "\n");
		*/
		i += step;
	}

	return 0;
}
