#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

typedef unsigned short u16;
typedef signed short s16;
typedef unsigned char u8;
typedef signed char s8;

typedef size_t (*inst_proc)(u8 const*, size_t);

#define SIGN_EXTEND(n) ((n & (u8)0x80) ? (n | (u16)0xff00) : (u16)n)
#define DATA16(data_lo, data_hi) (data_lo | (data_hi << (u16)8))

char const *register_mnemonics[16] = {
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
typedef char rm_buf_t[INST_ARG_BUF_SIZE];

static size_t render_rm(rm_buf_t buf, bool wide, u8 mod, u8 rm, u8 const *stream, size_t len) {
	u8 step = 0;
	switch (mod) {
		case 0:
			if (rm == 6) {
				step += 2;
				if (len < step) {
					return step;
				}
				/* direct address */
				snprintf(buf, INST_ARG_BUF_SIZE, "[%hu]", DATA16(stream[0], stream[1]));
			} else {
				snprintf(buf, INST_ARG_BUF_SIZE, "[%s]", eac_table[rm]);
			}
			break;
		case 1:
			step += 1;
			if (len < step) {
				return step;
			}
			/* TODO(benjamin): standard compliant signed conversion. */
			snprintf(buf, INST_ARG_BUF_SIZE, "[%s + %hi]", eac_table[rm], (s16)SIGN_EXTEND(stream[0]));
			break;
		case 2:
			step += 2;
			if (len < step) {
				return step;
			}
			/* TODO(benjamin): standard compliant signed conversion. */
			snprintf(buf, INST_ARG_BUF_SIZE, "[%s + %hi]", eac_table[rm], (s16)DATA16(stream[0], stream[1]));
			break;
		case 3:
			if (wide) {
				rm |= 0x08;
			}
			snprintf(buf, INST_ARG_BUF_SIZE, "%s", register_mnemonics[rm]);
			break;
	}
	return step;
}

static size_t render_r_to_rm(rm_buf_t r_buf, rm_buf_t rm_buf, u8 const *stream, size_t len) {
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
	snprintf(r_buf, INST_ARG_BUF_SIZE, "%s", register_mnemonics[r]);

	step += render_rm(rm_buf, wide, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	return step;
}

static size_t decode_r_to_rm(u8 const *stream, size_t len, char const *inst) {
	rm_buf_t r_buf;
	rm_buf_t rm_buf;
	u8 step = render_r_to_rm(r_buf, rm_buf, stream, len);

	if (step == 0) {
		return 0;
	}

	bool const reverse = (stream[0] & 0x2) != 0;

	if (reverse) {
		printf("%s %s, %s\n", inst, r_buf, rm_buf);
	} else {
		printf("%s %s, %s\n", inst, rm_buf, r_buf);
	}

	return step;
}

static size_t decode_r_vs_rm(u8 const *stream, size_t len, char const *inst) {
	rm_buf_t r_buf;
	rm_buf_t rm_buf;
	u8 step = render_r_to_rm(r_buf, rm_buf, stream, len);

	if (step == 0) {
		return 0;
	}

	printf("%s %s, %s\n", inst, r_buf, rm_buf);
	return step;
}

static size_t mov_immediate_to_reg(u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}
	bool const wide = !!(stream[0] & 0x08);
	u8 reg = stream[0] & 0x07;
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

	printf("mov %s, %hu\n", register_mnemonics[reg], immediate);
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
			printf("mov %s, byte %hu\n", register_mnemonics[b], SIGN_EXTEND(stream[2]));
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
			b |= 0x08;
			printf("mov %s, word %hu\n", register_mnemonics[b], DATA16(stream[2], stream[3]));
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
	u8 const rm = stream[1] & 0x7;

	rm_buf_t rm_buf;
	step += render_rm(rm_buf, wide, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
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

	printf("%s %s %s, %hu\n", arithmetic_mnemonics[op], wide?"word":"byte", rm_buf, immediate);
	return step;
}

static char const *const acc_mnemonics[2] = { "al", "ax" };

static size_t mov_mem2acc(bool wide, u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov %s, [%hu]\n", acc_mnemonics[wide], DATA16(stream[1], stream[2]));
	return 3;
}

static size_t mov_acc2mem(bool wide, u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], %s\n", DATA16(stream[1], stream[2]), acc_mnemonics[wide]);
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

static char const *const segment_register_mnemonics[4] = {
	"es",
	"cs",
	"ss",
	"ds",
};

static size_t segment_op(u8 const *stream, size_t len) {
	if (len < 1) {
		return 0;
	}

	u8 const reg = (stream[0] & 030u) >> 3u;

	if (stream[0] & 0x10u) {
		/* TODO(benjamin): segment override prefixes */
		return 0;
	} else {
		bool const pop = (stream[0] & 1u) != 0;
		printf("%s %s\n", pop?"pop":"push", segment_register_mnemonics[reg]);
	}

	return 1;
}

static size_t mov_seg_to_rm(u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	u8 const reverse = (stream[0] & 2u) != 0;
	u8 const mod = stream[1] >> 6u;
	/* TODO(benjamin): assert 040? */
	u8 const seg = (stream[1] & 030u) >> 3;
	u8 const rm = stream[1] & 07u;

	rm_buf_t rm_buf;
	step += render_rm(rm_buf, true, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	if (reverse) {
		printf("mov %s, %s\n", segment_register_mnemonics[seg], rm_buf);
	} else {
		printf("mov %s, %s\n", rm_buf, segment_register_mnemonics[seg]);
	}

	return 0;
}

static size_t lea_rm_to_r(u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	u8 const mod = stream[1] >> 6u;
	u8 const reg = ((stream[1] & 070u) >> 3u) | 8u;
	u8 const rm = stream[1] & 07u;

	rm_buf_t rm_buf;
	step += render_rm(rm_buf, true, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	printf("lea %s, %s\n", register_mnemonics[reg], rm_buf);
	return step;
}

static size_t pop_rm(u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	u8 const mod = stream[1] >> 6u;
	/* TODO(benjamin): assert 070? */
	u8 const rm = stream[1] & 07u;

	rm_buf_t rm_buf;
	step += render_rm(rm_buf, true, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	printf("pop %s\n", rm_buf);
	return step;
}

static size_t test_acc_immediate(bool wide, u8 const *stream, size_t len) {
	u8 const step = 2 + wide;
	if (len < step) {
		return 0;
	}

	if (wide) {
		printf("test ax, %hu", DATA16(stream[1], stream[2]));
	} else {
		printf("test al, %hu", stream[1]);
	}

	return step;
}

static char const *const shift_rot_mnemonics[8] = {
	"rol",
	"ror",
	"rcl",
	"rcr",
	"shl",
	"shr",
	NULL,
	"sar",
};

static size_t shift_rot_rm(u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	bool const cl = stream[0] & 2u;
	bool const wide = stream[0] & 1u;

	u8 const mod = stream[1] >> 6u;
	u8 const op = (stream[1] & 070u) >> 3u;
	u8 const rm = stream[1] & 7u;

	if (op == 6) {
		return 0;
	}

	rm_buf_t rm_buf;
	step += render_rm(rm_buf, wide, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	printf("%s %s, %s\n", shift_rot_mnemonics[op], rm_buf, cl?"cl":"1");
	return step;
}

static size_t string_op(char const *mnemonic, bool wide) {
	printf("rep %s%c\n", mnemonic, wide?'w':'b');
	return 1;
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
					return segment_op(stream, len);
				default:
					/* unreachable */
					return 0;
			}
		case 0x4:
			printf("%s %s\n", (stream[0] & 8u)?"dec":"inc", register_mnemonics[stream[0] & 7u]);
			return 1;
		case 0x5:
			printf("%s %s\n", (stream[0] & 8u)?"pop":"push", register_mnemonics[stream[0] & 7u]);
			return 1;
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
				case 0x4:
				case 0x5:
					return decode_r_vs_rm(stream, len, "test");
				case 0x6:
				case 0x7:
					return decode_r_vs_rm(stream, len, "xchg");
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:
					return decode_r_to_rm(stream, len, "mov");
				case 0xc:
					return mov_seg_to_rm(stream, len);
				case 0xd:
					return lea_rm_to_r(stream, len);
				case 0xe:
					return mov_seg_to_rm(stream, len);
				case 0xf:
					return pop_rm(stream, len);
				default:
					/* unreachable */
					return 0;
			}
		case 0x9:
			switch (stream[0] & 0xf) {
				case 0x0:
					/* NOTE(benjamin): xchg ax, ax */
					printf("nop\n");
					return 1;
				case 0x1:
				case 0x2:
				case 0x3:
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:
					printf("xchg ax, %s\n", register_mnemonics[stream[0] | 8u]);
					return 1;
				case 0x8:
					printf("cbw\n");
					return 1;
				case 0x9:
					printf("cwd\n");
					return 1;
				case 0xa:
					/* TODO(benjamin): not implemented: call */
					return 0;
				case 0xb:
					printf("wait\n");
					return 1;
				case 0xc:
					printf("pushf\n");
					return 1;
				case 0xd:
					printf("popf\n");
					return 1;
				case 0xe:
					printf("sahf\n");
					return 1;
				case 0xf:
					printf("lahf\n");
					return 1;
				default:
					/* unreachable. */
					return 0;
			}
		case 0xa:
			{
				bool const wide = stream[0] & 1u;
				switch ((stream[0] >> 1u) & 7u) {
					case 0:
						return mov_mem2acc(wide, stream, len);
					case 1:
						return mov_acc2mem(wide, stream, len);
					case 2:
						return string_op("movs", (stream[0] & 1u) != 0);
					case 3:
						return string_op("cmps", (stream[0] & 1u) != 0);
					case 4:
						return test_acc_immediate(wide, stream, len);
					case 5:
						return string_op("stos", (stream[0] & 1u) != 0);
					case 6:
						return string_op("lods", (stream[0] & 1u) != 0);
					case 7:
						return string_op("scas", (stream[0] & 1u) != 0);
					default:
						/* unreachable */
						return 0;
				}
			}
		case 0xb:
			return mov_immediate_to_reg(stream, len);
		case 0xc:
			switch (stream[0] & 0xf) {
				case 0x0:
				case 0x1:
					/* unused */
					return 0;
				case 0x2:
					if (len < 3) {
						return 0;
					}
					printf("ret %hu\n", DATA16(stream[1], stream[2]));
					return 3;
				case 0x3:
					printf("ret\n");
					return 1;
				case 0x4:
					/* TODO(benjamin): not implemented: les */
					return 0;
				case 0x5:
					/* TODO(benjamin): not implemented: lds */
					return 0;
				case 0x6:
					return mov_imm2narrow(stream, len);
				case 0x7:
					return mov_imm2wide(stream, len);
				case 0x8:
				case 0x9:
					/* unused */
					return 0;
				case 0xa:
					/* NOTE(benjamin): again?? intersegment? */
					if (len < 3) {
						return 0;
					}
					printf("ret %hu\n", DATA16(stream[1], stream[2]));
					return 3;
				case 0xb:
					/* NOTE(benjamin): again?? intersegment? */
					printf("ret\n");
					return 1;
				case 0xc:
					printf("int 3\n");
					return 1;
				case 0xd:
					if (len < 2) {
						return 0;
					}
					printf("int %hhu\n", stream[1]);
					return 2;
				case 0xe:
					printf("into\n");
					return 1;
				case 0xf:
					printf("iret\n");
					return 1;
				default:
					/* not implemented. */
					return 0;
			}
		case 0xd:
			switch (stream[0] & 0xfu) {
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:
					return shift_rot_rm(stream, len);
				case 0x4:
					printf("aam\n");
					return 1;
				case 0x5:
					printf("aad\n");
					return 1;
				case 0x6:
					/* unused */
					return 0;
				case 0x7:
					/* TODO(benjamin): not implemented: xlat */
					return 0;
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:
				case 0xc:
				case 0xd:
				case 0xe:
				case 0xf:
					/* TODO(benjamin): not implemented: esc */
					/* NOTE(benjamin): not supported by NASM? */
					return 0;
				default:
					/* unreachable */
					return 0;
			}
		case 0xe:
			switch (stream[0] & 0xf) {
				case 0x0:
				case 0x1:
				case 0x2:
				case 0x3:
					return extra_jump(stream, len);
				case 0x4:
					/* TODO(benjamin): not implemented: in al, immed8 */
					return 0;
				case 0x5:
					/* TODO(benjamin): not implemented: in ax, immed8 */
					return 0;
				case 0x6:
					/* TODO(benjamin): not implemented: out al, immed8 */
					return 0;
				case 0x7:
					/* TODO(benjamin): not implemented: out ax, immed8 */
					return 0;
				case 0x8:
					/* TODO(benjamin): not implemented: call near-proc */
					return 0;
				case 0x9:
					/* TODO(benjamin): not implemented: jmp near-label */
					return 0;
				case 0xa:
					/* TODO(benjamin): not implemented: jmp far-label */
					return 0;
				case 0xb:
					/* TODO(benjamin): not implemented: jmp short-label */
					return 0;
				case 0xc:
					/* TODO(benjamin): not implemented: in al, dx */
					return 0;
				case 0xd:
					/* TODO(benjamin): not implemented: in ax, dx */
					return 0;
				case 0xe:
					/* TODO(benjamin): not implemented: out al, dx */
					return 0;
				case 0xf:
					/* TODO(benjamin): not implemented: out ax, dx */
					return 0;
				default:
					/* unreachable */
					return 0;
			}
		case 0xf:
			/* TODO(benjamin): not implemented. */
			return 0;
		default:
			/* unreachable */
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
		i += step;
	}

	return 0;
}
