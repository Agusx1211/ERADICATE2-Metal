#ifndef HPP_TYPES
#define HPP_TYPES

// The structs declared in this file must have identical sizes and alignment
// between host code and GPU code. We avoid OpenCL headers and use fixed-width types.

#include <cstdint>

// Mirror of kernel-side enum. Keep ordering stable.
enum class ModeFunction : uint32_t {
	Benchmark = 0,
	ZeroBytes = 1,
	Matching = 2,
	Leading = 3,
	Range = 4,
	Mirror = 5,
	Doubles = 6,
	LeadingRange = 7
};

typedef struct {
	ModeFunction function;
	uint8_t data1[20];
	uint8_t data2[20];
} mode;

#pragma pack(push, 1)
typedef struct {
	uint8_t salt[32];
	uint8_t hash[20];
	uint32_t found;
} result;
#pragma pack(pop)

typedef union {
	uint8_t b[200];
	uint64_t q[25];
	uint32_t d[50];
} ethhash;

#endif /* HPP_TYPES */
