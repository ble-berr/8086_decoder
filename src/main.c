#include <stdio.h>
#include <unistd.h>

typedef unsigned short u16;
typedef unsigned char u8;

typedef size_t (*inst_proc)(u8 const*, size_t);

static inst_proc instruction_table[256];

char const *reg_names[16] = {
	"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
	"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
};

static void mov_rr(u8 from, u8 to) {
	if (from >= 16) {
		printf("mov: from is oob: %hhu", from);
	} else if (to >= 16) {
		printf("mov: to is oob: %hhu", to);
	} else {
		printf("mov %s, %s\n", reg_names[from], reg_names[to]);
	}
}

static size_t mov_narrow_to(u8 const *stream, size_t len) {
	if (!len) {
		return 0;
	}

	u8 byte_2 = stream[0];
	u8 mod = (byte_2 & 0xc0) >> 6;
	u8 a = (byte_2 & 0x38) >> 3;
	u8 b = (byte_2 & 0x07);

	if (mod == 0x3) {
		mov_rr(a, b);
	} else {
		printf("unsupported mov mod: 0x%02hhx\n", mod);
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

	if (mod == 0x3) {
		mov_rr(b, a);
	} else {
		printf("unsupported mov mod: 0x%02hhx\n", mod);
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
	u8 b = (byte_2 & 0x07) | 0x8;

	if (mod == 0x3) {
		mov_rr(a, b);
	} else {
		printf("unsupported mov mod: 0x%02hhx\n", mod);
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
	u8 b = (byte_2 & 0x07) | 0x8;

	if (mod == 0x3) {
		mov_rr(b, a);
	} else {
		printf("unsupported mov mod: 0x%02hhx\n", mod);
	}

	return 1;
}

#define PROGRAM_BUF_SIZE 512
int main(void) {
	u8 program[PROGRAM_BUF_SIZE];

	instruction_table[0x88] = &mov_narrow_from;
	instruction_table[0x89] = &mov_wide_from;
	instruction_table[0x8a] = &mov_narrow_to;
	instruction_table[0x8b] = &mov_wide_to;

	size_t program_len = read(0, program, 512);
	if (program_len == -1) {
		return 1;
	}
	if (program_len == PROGRAM_BUF_SIZE) {
		switch (read(0, program, 1)) {
			case -1:
				return 2;
			case 1:
				return 3;
			case 0:
				break;
			default:
				/* unreachable */
				return 4;
		}
	}

	for (size_t i = 0; i < program_len;) {
		inst_proc proc = instruction_table[program[i]];
		i += 1;
		if (proc) {
			i += proc(program + i, program_len - i);
		} else {
			printf("unrecognized instruction: 0x%02hhx\n", program[i]);
		}
	}

	return 0;
}
