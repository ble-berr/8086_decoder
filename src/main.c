#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

typedef unsigned short u16;
typedef signed short s16;
typedef unsigned char u8;
typedef signed char s8;

#define SIGN_EXTEND(n) ((n & (u8)0x80) ? (n | (u16)0xff00) : (u16)n)
#define DATA16(data_lo, data_hi) (data_lo | (data_hi << (u16)8))

enum register_id {
	REGISTER_AL,
	REGISTER_CL,
	REGISTER_DL,
	REGISTER_BL,
	REGISTER_AH,
	REGISTER_CH,
	REGISTER_DH,
	REGISTER_BH,
	REGISTER_AX,
	REGISTER_CX,
	REGISTER_DX,
	REGISTER_BX,
	REGISTER_SP,
	REGISTER_BP,
	REGISTER_SI,
	REGISTER_DI,
	REGISTER_ID_MAX,
};
char const *register_mnemonics[REGISTER_ID_MAX] = {
	"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
	"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
};

enum eac_base {
	EAC_SUM_BX_SI,
	EAC_SUM_BX_DI,
	EAC_SUM_BP_SI,
	EAC_SUM_BP_DI,
	EAC_SI,
	EAC_DI,
	EAC_BP,
	EAC_BX,
	/* used to size enum indexed arrays. */
	EAC_BASE_MAX,
};
static char const *eac_table[EAC_BASE_MAX] = {
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

enum operand_type {
	OPERAND_NONE,
	OPERAND_REGISTER,
	OPERAND_EFFECTIVE_ADDRESS,
	OPERAND_DIRECT_ADDRESS,
	OPERAND_IMMEDIATE_VALUE,
};

enum operand_width {
	OPERAND_WIDTH_BYTE,
	OPERAND_WIDTH_WORD,
	OPERAND_WIDTH_IMPLICIT,
};

struct instruction_operand {
	enum operand_type type;
	enum operand_width width;
	union {
		enum register_id register_id;
		struct eac {
			enum eac_base base;
			u16 offset;
		} eac;
		u16 direct_address;
		u16 immediate_value;
	};
};

enum instruction_type {
	INSTRUCTION_TYPE_AAD,
	INSTRUCTION_TYPE_AAM,
	INSTRUCTION_TYPE_ADC,
	INSTRUCTION_TYPE_ADD,
	INSTRUCTION_TYPE_AND,
	INSTRUCTION_TYPE_CBW,
	INSTRUCTION_TYPE_CLC,
	INSTRUCTION_TYPE_CLD,
	INSTRUCTION_TYPE_CLI,
	INSTRUCTION_TYPE_CMC,
	INSTRUCTION_TYPE_CMP,
	INSTRUCTION_TYPE_CMPSB,
	INSTRUCTION_TYPE_CMPSW,
	INSTRUCTION_TYPE_CWD,
	INSTRUCTION_TYPE_DEC,
	INSTRUCTION_TYPE_DIV,
	INSTRUCTION_TYPE_HLT,
	INSTRUCTION_TYPE_IDIV,
	INSTRUCTION_TYPE_IMUL,
	INSTRUCTION_TYPE_INC,
	INSTRUCTION_TYPE_INTO,
	INSTRUCTION_TYPE_IRET,
	INSTRUCTION_TYPE_JB,
	INSTRUCTION_TYPE_JBE,
	INSTRUCTION_TYPE_JCXZ,
	INSTRUCTION_TYPE_JE,
	INSTRUCTION_TYPE_JL,
	INSTRUCTION_TYPE_JLE,
	INSTRUCTION_TYPE_JNB,
	INSTRUCTION_TYPE_JNBE,
	INSTRUCTION_TYPE_JNE,
	INSTRUCTION_TYPE_JNL,
	INSTRUCTION_TYPE_JNLE,
	INSTRUCTION_TYPE_JNO,
	INSTRUCTION_TYPE_JNP,
	INSTRUCTION_TYPE_JNS,
	INSTRUCTION_TYPE_JO,
	INSTRUCTION_TYPE_JP,
	INSTRUCTION_TYPE_JS,
	INSTRUCTION_TYPE_LAHF,
	INSTRUCTION_TYPE_LODSB,
	INSTRUCTION_TYPE_LODSW,
	INSTRUCTION_TYPE_LOOP,
	INSTRUCTION_TYPE_LOOPE,
	INSTRUCTION_TYPE_LOOPNE,
	INSTRUCTION_TYPE_MOV,
	INSTRUCTION_TYPE_MOVSB,
	INSTRUCTION_TYPE_MOVSW,
	INSTRUCTION_TYPE_MUL,
	INSTRUCTION_TYPE_NEG,
	INSTRUCTION_TYPE_NOT,
	INSTRUCTION_TYPE_OR,
	INSTRUCTION_TYPE_POP,
	INSTRUCTION_TYPE_POPF,
	INSTRUCTION_TYPE_PUSH,
	INSTRUCTION_TYPE_PUSHF,
	INSTRUCTION_TYPE_RCL,
	INSTRUCTION_TYPE_RCR,
	INSTRUCTION_TYPE_RET,
	INSTRUCTION_TYPE_ROL,
	INSTRUCTION_TYPE_ROR,
	INSTRUCTION_TYPE_SAHF,
	INSTRUCTION_TYPE_SAR,
	INSTRUCTION_TYPE_SBB,
	INSTRUCTION_TYPE_SCASB,
	INSTRUCTION_TYPE_SCASW,
	INSTRUCTION_TYPE_SHL,
	INSTRUCTION_TYPE_SHR,
	INSTRUCTION_TYPE_STC,
	INSTRUCTION_TYPE_STD,
	INSTRUCTION_TYPE_STI,
	INSTRUCTION_TYPE_STOSB,
	INSTRUCTION_TYPE_STOSW,
	INSTRUCTION_TYPE_SUB,
	INSTRUCTION_TYPE_TEST,
	INSTRUCTION_TYPE_WAIT,
	INSTRUCTION_TYPE_XCHG,
	INSTRUCTION_TYPE_XLAT,
	INSTRUCTION_TYPE_XOR,
	/* can be used to size enum indexed arrays. */
	INSTRUCTION_TYPE_NONE,
};
char const *instruction_mnemonics[INSTRUCTION_TYPE_NONE] = {
	"aad",
	"aam",
	"adc",
	"add",
	"and",
	"cbw",
	"clc",
	"cld",
	"cli",
	"cmc",
	"cmp",
	"cmpsb",
	"cmpsw",
	"cwd",
	"dec",
	"div",
	"hlt",
	"idiv",
	"imul",
	"inc",
	"into",
	"iret",
	"jb",
	"jbe",
	"jcxz",
	"je",
	"jl",
	"jle",
	"jnb",
	"jnbe",
	"jne",
	"jnl",
	"jnle",
	"jno",
	"jnp",
	"jns",
	"jo",
	"jp",
	"js",
	"lahf",
	"lodsb",
	"lodsw",
	"loop",
	"loope",
	"loopne",
	"mov",
	"movsb",
	"movsw",
	"mul",
	"neg",
	"not",
	"or",
	"pop",
	"popf",
	"push",
	"pushf",
	"rcl",
	"rcr",
	"ret",
	"rol",
	"ror",
	"sahf",
	"sar",
	"sbb",
	"scasb",
	"scasw",
	"shl",
	"shr",
	"stc",
	"std",
	"sti",
	"stosb",
	"stosw",
	"sub",
	"test",
	"wait",
	"xchg",
	"xlat",
	"xor",
};

/* NOTE(benjamin): modeling the modifiers as a single enum might be too
 * simplistic. I am not sure whether any could be combined or not. */
enum instruction_modifier {
	INSTRUCTION_MODIFIER_LOCK,
	INSTRUCTION_MODIFIER_REPE,
	INSTRUCTION_MODIFIER_REPNE,
	/* can be used to size enum indexed arrays. */
	INSTRUCTION_MODIFIER_NONE,
};
char const *const instruction_modifier_mnemonics[INSTRUCTION_MODIFIER_NONE] = {
	"lock",
	"repe",
	"repne",
};

enum segment_override {
	SEGMENT_OVERRIDE_CS,
	SEGMENT_OVERRIDE_DS,
	SEGMENT_OVERRIDE_ES,
	SEGMENT_OVERRIDE_SS,
	/* can be used to size enum indexed arrays. */
	SEGMENT_OVERRIDE_NONE,
};
char const *const segment_override_mnemonics[SEGMENT_OVERRIDE_NONE] = {
	"cs",
	"ds",
	"es",
	"ss",
};

struct instruction {
	enum instruction_type type;
	enum instruction_modifier modifier;
	enum segment_override segment_override;
	struct instruction_operand dst;
	struct instruction_operand src;
};

static void clear_instruction(struct instruction *instruction) {
	assert(instruction != NULL);
	instruction->type = INSTRUCTION_TYPE_NONE;
	instruction->modifier = INSTRUCTION_MODIFIER_NONE;
	instruction->segment_override = SEGMENT_OVERRIDE_NONE;

	instruction->dst.type = OPERAND_NONE;
	instruction->dst.width = OPERAND_WIDTH_IMPLICIT;

	instruction->src.type = OPERAND_NONE;
	instruction->src.width = OPERAND_WIDTH_IMPLICIT;
}

static void print_instruction_operand(struct instruction_operand const *operand) {
	assert(operand != NULL);

	switch (operand->width) {
		case OPERAND_WIDTH_IMPLICIT:
			break;
		case OPERAND_WIDTH_BYTE:
			printf("byte ");
			break;
		case OPERAND_WIDTH_WORD:
			printf("word ");
			break;
	}

	switch (operand->type) {
		case OPERAND_NONE:
			return;
		case OPERAND_REGISTER:
			printf("%s", register_mnemonics[operand->register_id]);
			break;
		case OPERAND_EFFECTIVE_ADDRESS:
			printf("[%s", eac_table[operand->eac.base]);
			if (operand->eac.offset) {
				printf(" + %hi", (s16)operand->eac.offset);
			}
			printf("]");
			break;
		case OPERAND_DIRECT_ADDRESS:
			printf("[%hu]", operand->direct_address);
			break;
		case OPERAND_IMMEDIATE_VALUE:
			printf("%hu", operand->immediate_value);
			break;
	}
}

static void print_instruction(struct instruction const *instruction) {
	assert(instruction != NULL);
	if (instruction->type == INSTRUCTION_TYPE_NONE) {
		return;
	}

	if (instruction->modifier != INSTRUCTION_MODIFIER_NONE) {
		printf("%s ", instruction_modifier_mnemonics[instruction->modifier]);
	}
	printf("%s", instruction_mnemonics[instruction->type]);

	if (instruction->dst.type == OPERAND_NONE) {
		return;
	}
	printf(" ");
	if (instruction->segment_override != SEGMENT_OVERRIDE_NONE) {
		printf("%s:", segment_override_mnemonics[instruction->segment_override]);
	}

	print_instruction_operand(&instruction->dst);

	if (instruction->src.type == OPERAND_NONE) {
		return;
	}
	printf(", ");

	print_instruction_operand(&instruction->src);

	return;
}

/*
 * A mod byte is a recurring structured byte in the x86 instruction set:
 * bits : |7 6|5 4 3|2 1 0|
 * field: |mod|  a  |  b  |
 */
struct mod_byte {
	u8 mod;
	u8 a;
	u8 b;
};

static struct mod_byte parse_mod_byte(u8 byte) {
	struct mod_byte b = {
		(byte & 0300u) >> 6,
		(byte & 0070u) >> 3,
		(byte & 0007u) >> 0,
	};
	return b;
}

static size_t process_mod_operand(
		struct instruction_operand *operand,
		bool wide,
		u8 mod,
		u8 rm,
		u8 const *stream,
		size_t len
		)
{
	assert(operand);
	u8 step = 0;
	switch (mod) {
		case 0:
			if (rm == 6) {
				step += 2;
				if (len < step) {
					return step;
				}
				operand->type = OPERAND_DIRECT_ADDRESS;
				operand->direct_address = DATA16(stream[0], stream[1]);
			} else {
				operand->type = OPERAND_EFFECTIVE_ADDRESS;
				operand->eac.base = rm;
				operand->eac.offset = 0;
			}
			break;
		case 1:
			step += 1;
			if (len < step) {
				return step;
			}
			operand->type = OPERAND_EFFECTIVE_ADDRESS;
			operand->eac.base = rm;
			operand->eac.offset = SIGN_EXTEND(stream[0]);
			break;
		case 2:
			step += 2;
			if (len < step) {
				return step;
			}
			operand->type = OPERAND_EFFECTIVE_ADDRESS;
			operand->eac.base = rm;
			operand->eac.offset = DATA16(stream[0], stream[1]);
			break;
		case 3:
			if (wide) {
				rm |= 0x08;
			}
			operand->type = OPERAND_REGISTER;
			operand->register_id = rm;
			break;
	}
	return step;
}

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
		printf("%s %s, %s", inst, r_buf, rm_buf);
	} else {
		printf("%s %s, %s", inst, rm_buf, r_buf);
	}

	return step;
}

static size_t decode_r_vs_rm(struct instruction *instruction, u8 const *stream, size_t len) {
	assert(instruction);

	size_t step = 2;
	if (len < step) {
		return step;
	}

	bool const wide = (stream[0] & 0x1u) != 0;
	bool const xchg = (stream[0] & 0x2u) != 0;

	struct mod_byte op_fields = parse_mod_byte(stream[1]);

	/* a is a register */
	if (wide) {
		op_fields.a |= 010u;
	}

	if (xchg) {
		instruction->type = INSTRUCTION_TYPE_XCHG;
		instruction->dst.type = OPERAND_REGISTER;
		instruction->dst.register_id = op_fields.a;
		step += process_mod_operand(
				&instruction->src,
				wide,
				op_fields.mod,
				op_fields.b,
				stream + step,
				len - step);
		if (len < step) {
			return step;
		}
	} else {
		instruction->type = INSTRUCTION_TYPE_TEST;
		step += process_mod_operand(
				&instruction->dst,
				wide,
				op_fields.mod,
				op_fields.b,
				stream + step,
				len - step);
		if (len < step) {
			return step;
		}
		instruction->src.type = OPERAND_REGISTER;
		instruction->src.register_id = op_fields.a;
	}
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

	printf("mov %s, %hu", register_mnemonics[reg], immediate);
	return step;
}

static size_t mov_immediate_to_mem(struct instruction *instruction, bool wide, u8 const *stream, size_t len) {
	assert(instruction);

	instruction->type = INSTRUCTION_TYPE_MOV;

	size_t step = 2;
	if (len < step) {
		return 0;
	}

	/* assert value of mb.a? */
	struct mod_byte mb = parse_mod_byte(stream[1]);

	step += process_mod_operand(&instruction->dst, wide, mb.mod, mb.b, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	instruction->src.type = OPERAND_IMMEDIATE_VALUE;
	instruction->src.width = wide ? OPERAND_WIDTH_WORD : OPERAND_WIDTH_BYTE;
	if (wide) {
		step += 2;
		if (len < step) {
			return 0;
		}
		instruction->src.immediate_value = DATA16(stream[step - 2], stream[step - 1]);
	} else {
		step += 1;
		if (len < step) {
			return 0;
		}
		instruction->src.immediate_value = stream[step - 1];
	}

	return step;
}

static size_t op_acc_immediate(u8 const *stream, size_t len, char const *mnemonic) {
	bool const wide = (stream[0] & 0x1u) != 0;
	u8 const step = 2 + wide;
	if (len < step) {
		return 0;
	}

	if (wide) {
		printf("%s ax, word %hu", mnemonic, DATA16(stream[1], stream[2]));
	} else {
		/* TODO(benjamin): standard compliant signed conversion. */
		printf("%s al, byte %hhi", mnemonic, (s8)stream[1]);
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

	printf("%s %s %s, %hu", arithmetic_mnemonics[op], wide?"word":"byte", rm_buf, immediate);
	return step;
}

static char const *const acc_mnemonics[2] = { "al", "ax" };

static size_t mov_mem2acc(bool wide, u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov %s, [%hu]", acc_mnemonics[wide], DATA16(stream[1], stream[2]));
	return 3;
}

static size_t mov_acc2mem(bool wide, u8 const *stream, size_t len) {
	/* TODO(benjamin): assert len. */
	printf("mov [%hu], %s", DATA16(stream[1], stream[2]), acc_mnemonics[wide]);
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
	printf("%s $%+hhi", conditional_jump_mnemonics[stream[0] & 0xf], ip_inc_8);
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
	printf("%s $%+hhi", extra_jump_mnemonics[stream[0] & 0x3], ip_inc_8);
	return 2;
}

static char const *const segment_register_mnemonics[4] = {
	"es",
	"cs",
	"ss",
	"ds",
};

static size_t misc_0x30_ops(u8 const *stream, size_t len) {
	if (len < 1) {
		return 0;
	}


	switch (stream[0] & 0x21u) {
		case 0x00:
			{
				u8 const reg = (stream[0] & 030u) >> 3u;
				printf("push %s", segment_register_mnemonics[reg]);
			}
			break;
		case 0x01:
			if (stream[0] == 0x0fu) {
				/* unused. */
				return 0;
			} else {
				u8 const reg = (stream[0] & 030u) >> 3u;
				printf("pop %s", segment_register_mnemonics[reg]);
			}
			break;
		case 0x20:
			/* TODO(benjamin): not implemented: segment operations */
			return 0;
		case 0x21:
			{
				char const *mnemonics[4] = { "daa", "das", "aaa", "aas" };
				u8 const index = (stream[0] & 0x18u) >> 3u;
				printf("%s", mnemonics[index]);
			}
			return 1;
		default:
			/* unreachable */
			return 0;
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
		printf("mov %s, %s", segment_register_mnemonics[seg], rm_buf);
	} else {
		printf("mov %s, %s", rm_buf, segment_register_mnemonics[seg]);
	}

	return 0;
}

static size_t load_rm_to_r(char const *op_mnemonic, u8 const *stream, size_t len) {
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

	printf("%s %s, %s", op_mnemonic, register_mnemonics[reg], rm_buf);
	return step;
}

static size_t pop_rm(bool wide, u8 const *stream, size_t len) {
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

	printf("pop %s %s", wide?"word":"byte", rm_buf);
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

	printf("%s %s %s, %s", shift_rot_mnemonics[op], wide?"word":"byte", rm_buf, cl?"cl":"1");
	return step;
}

static size_t acc_io_op(u8 const *stream, size_t len) {
	if (len < 1) {
		return 0;
	}

	bool const immediate = (stream[0] & 8u) == 0;
	bool const out = (stream[0] & 2u) != 0;
	bool const wide = (stream[0] & 1u) != 0;

	if (immediate) {
		if (len < 2) {
			return 0;
		}
		if (out) {
			printf("out %hu, %s", stream[1], acc_mnemonics[wide]);
		} else {
			printf("in %s, %hu", acc_mnemonics[wide], stream[1]);
		}
		return 2;
	} else {
		if (out) {
			printf("out dx, %s", acc_mnemonics[wide]);
		} else {
			printf("in %s, dx", acc_mnemonics[wide]);
		}
		return 1;
	}
}

static char const *const ff_extra_ops_mnemonics[8] = {
	"inc",
	"dec",
	"call",
	"call",
	"jmp",
	"jmp",
	"push",
	/* 7 is unused. */
	NULL,
};

static size_t ff_extra_ops(u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	u8 const mod = stream[1] >> 6u;
	u8 const op = (stream[1] & 070u) >> 3u;
	u8 const rm = stream[1] & 7u;

	if (op == 7) {
		/* unused */
		return 0;
	}

	rm_buf_t rm_buf;
	step += render_rm(rm_buf, true, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	printf("%s word %s", ff_extra_ops_mnemonics[op], rm_buf);
	return step;
}

static size_t f7_extra_ops(struct instruction *instruction, u8 const *stream, size_t len) {
	u8 step = 2;
	if (len < step) {
		return 0;
	}

	bool const wide = (stream[0] & 1u) != 0;
	u8 const mod = stream[1] >> 6u;
	u8 const op = (stream[1] >> 3u) & 7u;
	u8 const rm = stream[1] & 7u;

	if (op == 1) {
		/* unused */
		return 0;
	}

	step += process_mod_operand(&instruction->dst, wide, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	switch (op) {
		case 0:
			instruction->type = INSTRUCTION_TYPE_TEST;
			instruction->src.type = OPERAND_IMMEDIATE_VALUE;
			if (wide) {
				step += 2;
				if (len < step) {
					return 0;
				}
				instruction->src.width = OPERAND_WIDTH_WORD;
				instruction->src.immediate_value = DATA16(stream[step - 2], stream[step - 1]);
			} else {
				step += 1;
				if (len < step) {
					return 0;
				}
				instruction->src.width = OPERAND_WIDTH_BYTE;
				instruction->src.immediate_value = stream[step - 1];
			}
			break;
		case 2:
			instruction->type = INSTRUCTION_TYPE_NOT;
			instruction->dst.width = wide ? OPERAND_WIDTH_WORD : OPERAND_WIDTH_BYTE;
			break;
		case 3:
			instruction->type = INSTRUCTION_TYPE_NEG;
			instruction->dst.width = wide ? OPERAND_WIDTH_WORD : OPERAND_WIDTH_BYTE;
			break;
		case 4:
			instruction->type = INSTRUCTION_TYPE_MUL;
			instruction->dst.width = wide ? OPERAND_WIDTH_WORD : OPERAND_WIDTH_BYTE;
			break;
		case 5:
			instruction->type = INSTRUCTION_TYPE_IMUL;
			instruction->dst.width = wide ? OPERAND_WIDTH_WORD : OPERAND_WIDTH_BYTE;
			break;
		case 6:
			instruction->type = INSTRUCTION_TYPE_DIV;
			instruction->dst.width = wide ? OPERAND_WIDTH_WORD : OPERAND_WIDTH_BYTE;
			break;
		case 7:
			instruction->type = INSTRUCTION_TYPE_IDIV;
			instruction->dst.width = wide ? OPERAND_WIDTH_WORD : OPERAND_WIDTH_BYTE;
			break;
		case 1: /* unused */
		default: /* unreachable */
			return 0;
	}
	return step;
}

static size_t inc_dec_rm8(u8 const *stream, size_t len) {
	size_t step = 2;
	if (len < step) {
		return 0;
	}

	u8 const mod = stream[1] >> 6u;
	/* NOTE(benjamin): assert that bits 4 and 5 are 0? */
	bool const decrement = (stream[1] & 010u) != 0;
	u8 const rm = stream[1] & 07u;

	rm_buf_t rm_buf;
	step += render_rm(rm_buf, false, mod, rm, stream + step, len - step);
	if (len < step) {
		return 0;
	}

	printf("%s byte %s", decrement?"dec":"inc", rm_buf);
	return step;
}

static size_t dispatch(u8 const *stream, size_t len, struct instruction *instruction) {
	assert(stream);
	assert(instruction);
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
					return misc_0x30_ops(stream, len);
				default:
					/* unreachable */
					return 0;
			}
		case 0x4:
			instruction->type = (stream[0] & 8u) ? INSTRUCTION_TYPE_DEC : INSTRUCTION_TYPE_INC;
			instruction->dst.type = OPERAND_REGISTER;
			instruction->dst.register_id = (stream[0] & 7u) | 8u;
			instruction->src.type = OPERAND_NONE;
			return 1;
		case 0x5:
			instruction->type = (stream[0] & 8u) ? INSTRUCTION_TYPE_POP : INSTRUCTION_TYPE_PUSH;
			instruction->dst.type = OPERAND_REGISTER;
			instruction->dst.register_id = (stream[0] & 7u) | 8u;
			instruction->src.type = OPERAND_NONE;
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
				case 0x6:
				case 0x7:
					return decode_r_vs_rm(instruction, stream, len);
				case 0x8:
				case 0x9:
				case 0xa:
				case 0xb:
					return decode_r_to_rm(stream, len, "mov");
				case 0xc:
					return mov_seg_to_rm(stream, len);
				case 0xd:
					return load_rm_to_r("lea", stream, len);
				case 0xe:
					return mov_seg_to_rm(stream, len);
				case 0xf:
					return pop_rm(true, stream, len);
				default:
					/* unreachable */
					return 0;
			}
		case 0x9:
			switch (stream[0] & 0xf) {
				case 0x0: /* NOTE(benjamin): nop (xchg ax, ax) */
				case 0x1:
				case 0x2:
				case 0x3:
				case 0x4:
				case 0x5:
				case 0x6:
				case 0x7:
					instruction->type = INSTRUCTION_TYPE_XCHG;
					instruction->dst.type = OPERAND_REGISTER;
					instruction->dst.register_id = REGISTER_AX;
					instruction->src.type = OPERAND_REGISTER;
					instruction->src.register_id = (stream[0] & 7u) | 8u;
					return 1;
				case 0x8:
					instruction->type = INSTRUCTION_TYPE_CBW;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0x9:
					instruction->type = INSTRUCTION_TYPE_CWD;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xa:
					/* TODO(benjamin): not implemented: call */
					return 0;
				case 0xb:
					instruction->type = INSTRUCTION_TYPE_WAIT;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xc:
					instruction->type = INSTRUCTION_TYPE_PUSHF;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xd:
					instruction->type = INSTRUCTION_TYPE_POPF;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xe:
					instruction->type = INSTRUCTION_TYPE_SAHF;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xf:
					instruction->type = INSTRUCTION_TYPE_LAHF;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
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
						instruction->type = (stream[0] & 1u) ?
							INSTRUCTION_TYPE_MOVSW : INSTRUCTION_TYPE_MOVSB;
						return 1;
					case 3:
						instruction->type = (stream[0] & 1u) ?
							INSTRUCTION_TYPE_CMPSW : INSTRUCTION_TYPE_CMPSB;
						return 1;
					case 4:
						return test_acc_immediate(wide, stream, len);
					case 5:
						instruction->type = (stream[0] & 1u) ?
							INSTRUCTION_TYPE_STOSW : INSTRUCTION_TYPE_STOSB;
						return 1;
					case 6:
						instruction->type = (stream[0] & 1u) ?
							INSTRUCTION_TYPE_LODSW : INSTRUCTION_TYPE_LODSB;
						return 1;
					case 7:
						instruction->type = (stream[0] & 1u) ?
							INSTRUCTION_TYPE_SCASW : INSTRUCTION_TYPE_SCASB;
						return 1;
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
					printf("ret %hu", DATA16(stream[1], stream[2]));
					return 3;
				case 0x3:
					instruction->type = INSTRUCTION_TYPE_RET;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0x4:
					return load_rm_to_r("les", stream, len);
				case 0x5:
					return load_rm_to_r("lds", stream, len);
				case 0x6:
					return mov_immediate_to_mem(instruction, false, stream, len);
				case 0x7:
					return mov_immediate_to_mem(instruction, true, stream, len);
				case 0x8:
				case 0x9:
					/* unused */
					return 0;
				case 0xa:
					/* NOTE(benjamin): again?? intersegment? */
					if (len < 3) {
						return 0;
					}
					printf("ret %hu", DATA16(stream[1], stream[2]));
					return 3;
				case 0xb:
					/* NOTE(benjamin): again?? intersegment? */
					instruction->type = INSTRUCTION_TYPE_RET;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xc:
					printf("int 3");
					return 1;
				case 0xd:
					if (len < 2) {
						return 0;
					}
					printf("int %hhu", stream[1]);
					return 2;
				case 0xe:
					instruction->type = INSTRUCTION_TYPE_INTO;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xf:
					instruction->type = INSTRUCTION_TYPE_IRET;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
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
					/* NOTE(benjamin): assert stream[1] == 0x0a ? */
					instruction->type = INSTRUCTION_TYPE_AAM;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 2;
				case 0x5:
					/* NOTE(benjamin): assert stream[1] == 0x0a ? */
					instruction->type = INSTRUCTION_TYPE_AAD;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 2;
				case 0x6:
					/* unused */
					return 0;
				case 0x7:
					instruction->type = INSTRUCTION_TYPE_XLAT;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
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
				case 0x5:
				case 0x6:
				case 0x7:
					return acc_io_op(stream, len);
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
				case 0xd:
				case 0xe:
				case 0xf:
					return acc_io_op(stream, len);
				default:
					/* unreachable */
					return 0;
			}
		case 0xf:
			switch (stream[0] & 0xf) {
				case 0x0:
					instruction->modifier = INSTRUCTION_MODIFIER_LOCK;
					return 1;
				case 0x1:
					/* unused */
					return 0;
				case 0x2:
					instruction->modifier = INSTRUCTION_MODIFIER_REPNE;
					return 1;
				case 0x3:
					instruction->modifier = INSTRUCTION_MODIFIER_REPE;
					return 1;
				case 0x4:
					instruction->type = INSTRUCTION_TYPE_HLT;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0x5:
					instruction->type = INSTRUCTION_TYPE_CMC;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0x6:
				case 0x7:
					return f7_extra_ops(instruction, stream, len);
				case 0x8:
					instruction->type = INSTRUCTION_TYPE_CLC;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0x9:
					instruction->type = INSTRUCTION_TYPE_STC;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xa:
					instruction->type = INSTRUCTION_TYPE_CLI;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xb:
					instruction->type = INSTRUCTION_TYPE_STI;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xc:
					instruction->type = INSTRUCTION_TYPE_CLD;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xd:
					instruction->type = INSTRUCTION_TYPE_STD;
					instruction->dst.type = OPERAND_NONE;
					instruction->src.type = OPERAND_NONE;
					return 1;
				case 0xe:
					return inc_dec_rm8(stream, len);
				case 0xf:
					return ff_extra_ops(stream, len);
				default:
					/* unreachable */
					return 0;
			}
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

	struct instruction instruction;
	clear_instruction(&instruction);

	for (size_t i = 0; i < program_len;) {
		size_t const step = dispatch(program + i, program_len - i, &instruction);
		if (!step) {
			printf("; unrecognized instruction: program[0x%zx]: 0x%02hhx\n", i, program[i]);
			return 0;
		}

		if (instruction.type != INSTRUCTION_TYPE_NONE) {
			print_instruction(&instruction);
			clear_instruction(&instruction);
		}

		printf(" ;");
		for (size_t j = 0; j < step; ++j) {
			printf(" 0x%02hhx", program[i + j]);
		}
		printf("\n");

		i += step;
	}

	return 0;
}
