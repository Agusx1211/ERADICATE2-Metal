#include <metal_stdlib>
using namespace metal;

enum ModeFunction : uint32_t {
    Benchmark    = 0,
    ZeroBytes    = 1,
    Matching     = 2,
    Leading      = 3,
    Range        = 4,
    Mirror       = 5,
    Doubles      = 6,
    LeadingRange = 7
};

struct mode {
    ModeFunction function;
    uchar data1[20];
    uchar data2[20];
};

struct result {
    uchar       salt[32];
    uchar       hash[20];
    atomic_uint found;
};

inline __attribute__((always_inline)) ulong rotl64(ulong x, uint n) {
    return (x << n) | (x >> (64 - n));
}

// FIXED: round 8 constant (index 7) must have the MSB set.
constant ulong keccakf_rndc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

inline __attribute__((always_inline)) void sha3_keccakf(thread ulong st[25]) {
    // keep identical to your kernel
    st[16] ^= (ulong)0x80000000UL << 32;

    for (int i = 0; i < 24; ++i) {
        // THETA (same mapping)
        ulong t0, t1, t2, t3, t4, t5;
        t0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        t1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        t2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        t3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        t4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        t5 = rotl64(t0, 1) ^ t3;
        t0 = rotl64(t2, 1) ^ t0;
        t2 = rotl64(t4, 1) ^ t2;
        t4 = rotl64(t1, 1) ^ t4;
        t1 = rotl64(t3, 1) ^ t1;

        st[0] ^= t4; st[5] ^= t4; st[10] ^= t4; st[15] ^= t4; st[20] ^= t4;
        st[1] ^= t0; st[6] ^= t0; st[11] ^= t0; st[16] ^= t0; st[21] ^= t0;
        st[2] ^= t1; st[7] ^= t1; st[12] ^= t1; st[17] ^= t1; st[22] ^= t1;
        st[3] ^= t2; st[8] ^= t2; st[13] ^= t2; st[18] ^= t2; st[23] ^= t2;
        st[4] ^= t5; st[9] ^= t5; st[14] ^= t5; st[19] ^= t5; st[24] ^= t5;

        // RHO+PI (same order)
        ulong t = rotl64(st[1], 1);
        st[1]  = rotl64(st[6], 44);
        st[6]  = rotl64(st[9], 20);
        st[9]  = rotl64(st[22], 61);
        st[22] = rotl64(st[14], 39);
        st[14] = rotl64(st[20], 18);
        st[20] = rotl64(st[2], 62);
        st[2]  = rotl64(st[12], 43);
        st[12] = rotl64(st[13], 25);
        st[13] = rotl64(st[19], 8);
        st[19] = rotl64(st[23], 56);
        st[23] = rotl64(st[15], 41);
        st[15] = rotl64(st[4], 27);
        st[4]  = rotl64(st[24], 14);
        st[24] = rotl64(st[21], 2);
        st[21] = rotl64(st[8], 55);
        st[8]  = rotl64(st[16], 45);
        st[16] = rotl64(st[5], 36);
        st[5]  = rotl64(st[3], 28);
        st[3]  = rotl64(st[18], 21);
        st[18] = rotl64(st[17], 15);
        st[17] = rotl64(st[11], 10);
        st[11] = rotl64(st[7], 6);
        st[7]  = rotl64(st[10], 3);
        st[10] = t;

        // CHI
        ulong a0=st[0],  a1=st[1];  st[0] ^= (~a1) & st[2];  st[1] ^= (~st[2])  & st[3];  st[2] ^= (~st[3])  & st[4];  st[3] ^= (~st[4])  & a0;  st[4] ^= (~a0)  & a1;
        a0=st[5];  a1=st[6];  st[5] ^= (~a1) & st[7];  st[6] ^= (~st[7])  & st[8];  st[7] ^= (~st[8])  & st[9];  st[8] ^= (~st[9])  & a0;  st[9] ^= (~a0)  & a1;
        a0=st[10]; a1=st[11]; st[10]^= (~a1) & st[12]; st[11]^= (~st[12]) & st[13]; st[12]^= (~st[13]) & st[14]; st[13]^= (~st[14]) & a0;  st[14]^= (~a0) & a1;
        a0=st[15]; a1=st[16]; st[15]^= (~a1) & st[17]; st[16]^= (~st[17]) & st[18]; st[17]^= (~st[18]) & st[19]; st[18]^= (~st[19]) & a0;  st[19]^= (~a0) & a1;
        a0=st[20]; a1=st[21]; st[20]^= (~a1) & st[22]; st[21]^= (~st[22]) & st[23]; st[22]^= (~st[23]) & st[24]; st[23]^= (~st[24]) & a0;  st[24]^= (~a0) & a1;

        // IOTA
        st[0] ^= keccakf_rndc[i];
    }
}

// Emit salt bytes [21..52] directly (same as copying out_b[21..52]).
inline __attribute__((always_inline)) void emit_salt_21_52(thread const ulong st[25], thread uchar out32[32]) {
    ulong s2 = st[2], s3 = st[3], s4 = st[4], s5 = st[5], s6 = st[6];

    out32[0] = (uchar)((s2 >> 40) & 0xFF);
    out32[1] = (uchar)((s2 >> 48) & 0xFF);
    out32[2] = (uchar)((s2 >> 56) & 0xFF);

    #pragma clang loop unroll(full)
    for (uint j = 0; j < 8; ++j) out32[3  + j] = (uchar)((s3 >> (8*j)) & 0xFF);
    #pragma clang loop unroll(full)
    for (uint j = 0; j < 8; ++j) out32[11 + j] = (uchar)((s4 >> (8*j)) & 0xFF);
    #pragma clang loop unroll(full)
    for (uint j = 0; j < 8; ++j) out32[19 + j] = (uchar)((s5 >> (8*j)) & 0xFF);
    #pragma clang loop unroll(full)
    for (uint j = 0; j < 5; ++j) out32[27 + j] = (uchar)((s6 >> (8*j)) & 0xFF);
}

inline __attribute__((always_inline)) void eradicate2_result_update(thread const uchar *H,
                                                                    device result *pResult,
                                                                    uchar score,
                                                                    uchar scoreMax,
                                                                    uint deviceIndex,
                                                                    uint gid,
                                                                    uint round,
                                                                    constant ulong *st_init) {
    if (score == 0 || score <= scoreMax) return;

    device result *r = &pResult[score];
    uint prev = atomic_fetch_add_explicit(&r->found, 1, memory_order_relaxed);
    if (prev != 0) return;

    ulong st_local[25];
    #pragma clang loop unroll(full)
    for (uint i = 0; i < 25; ++i) st_local[i] = st_init[i];

    uint lo3 = (uint)(st_local[3] & 0xFFFFFFFFUL);
    uint hi3 = (uint)(st_local[3] >> 32);
    lo3 = (uint)(lo3 + (uint)deviceIndex);
    hi3 = (uint)(hi3 + (uint)gid);
    st_local[3] = ((ulong)hi3 << 32) | (ulong)lo3;

    uint lo4 = (uint)(st_local[4] & 0xFFFFFFFFUL);
    uint hi4 = (uint)(st_local[4] >> 32);
    lo4 = (uint)(lo4 + (uint)round);
    st_local[4] = ((ulong)hi4 << 32) | (ulong)lo4;

    uchar salt32[32];
    emit_salt_21_52(st_local, salt32);
    #pragma clang loop unroll(full)
    for (uint i = 0; i < 32; ++i) r->salt[i] = salt32[i];

    #pragma clang loop unroll(full)
    for (uint i = 0; i < 20; ++i) r->hash[i] = H[i];
}

// --- scoring (semantics identical to your original) ---

inline __attribute__((always_inline)) void eradicate2_score_leading(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    int score = 0;
    uchar nib = pMode->data1[0]; // no masking
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 20; ++i) {
        if (((hash[i] & 0xF0) >> 4) == nib) { ++score; } else { break; }
        if ( (hash[i] & 0x0F)       == nib) { ++score; } else { break; }
    }
    eradicate2_result_update(hash, pResult, (uchar)score, scoreMax, deviceIndex, gid, round, st_init);
}

inline __attribute__((always_inline)) void eradicate2_score_benchmark(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    (void)hash; (void)pResult; (void)pMode; (void)scoreMax; (void)deviceIndex; (void)gid; (void)round; (void)st_init;
}

inline __attribute__((always_inline)) void eradicate2_score_zerobytes(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    int score = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 20; ++i) score += (hash[i] == 0);
    eradicate2_result_update(hash, pResult, (uchar)score, scoreMax, deviceIndex, gid, round, st_init);
}

inline __attribute__((always_inline)) void eradicate2_score_matching(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    int score = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 20; ++i) {
        uchar mask = pMode->data1[i];
        score += (mask > 0 && (uchar)(hash[i] & mask) == pMode->data2[i]);
    }
    eradicate2_result_update(hash, pResult, (uchar)score, scoreMax, deviceIndex, gid, round, st_init);
}

inline __attribute__((always_inline)) void eradicate2_score_range(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    int score = 0;
    uchar lo = pMode->data1[0]; // no masking
    uchar hi = pMode->data2[0];
    #pragma clang loop unroll(full)
    for (int i = 0; i < 20; ++i) {
        uchar first  = (hash[i] & 0xF0) >> 4;
        uchar second =  hash[i] & 0x0F;
        score += (first  >= lo && first  <= hi);
        score += (second >= lo && second <= hi);
    }
    eradicate2_result_update(hash, pResult, (uchar)score, scoreMax, deviceIndex, gid, round, st_init);
}

inline __attribute__((always_inline)) void eradicate2_score_leadingrange(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    int score = 0;
    uchar lo = pMode->data1[0]; // no masking
    uchar hi = pMode->data2[0];
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 20; ++i) {
        uchar first  = (hash[i] & 0xF0) >> 4;
        if (!(first >= lo && first <= hi)) break; ++score;
        uchar second =  hash[i] & 0x0F;
        if (!(second >= lo && second <= hi)) break; ++score;
    }
    eradicate2_result_update(hash, pResult, (uchar)score, scoreMax, deviceIndex, gid, round, st_init);
}

inline __attribute__((always_inline)) void eradicate2_score_mirror(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    int score = 0;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 10; ++i) {
        uchar L  = hash[9  - i];
        uchar R  = hash[10 + i];
        uchar leftRight  =  L       & 0x0F;
        uchar leftLeft   = (L >> 4) & 0x0F;
        uchar rightLeft  = (R >> 4) & 0x0F;
        uchar rightRight =  R       & 0x0F;
        if (leftRight != rightLeft) break; ++score;
        if (leftLeft  != rightRight) break; ++score;
    }
    eradicate2_result_update(hash, pResult, (uchar)score, scoreMax, deviceIndex, gid, round, st_init);
}

inline __attribute__((always_inline)) void eradicate2_score_doubles(thread const uchar *hash, device result *pResult, thread const mode *pMode, uchar scoreMax, uint deviceIndex, uint gid, uint round, constant ulong *st_init) {
    int score = 0;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 20; ++i) {
        uchar v = hash[i];
        bool isdbl = (((v ^ (v >> 4)) & 0x0F) == 0u); // 00,11,...,FF
        if (isdbl) { ++score; } else { break; }
    }
    eradicate2_result_update(hash, pResult, (uchar)score, scoreMax, deviceIndex, gid, round, st_init);
}

kernel void eradicate2_iterate(device result       *pResult     [[buffer(0)]],
                               device const mode   *pMode       [[buffer(1)]],
                               constant uchar      &scoreMax    [[buffer(2)]],
                               constant uint       &deviceIndex [[buffer(3)]],
                               constant uint       &round       [[buffer(4)]],
                               constant ulong      *initQ       [[buffer(5)]],
                               uint gid                           [[thread_position_in_grid]]) {
    thread mode m = *pMode; // bring to registers

    // (Optional micro-early-out—safe for correctness, can remove if you prefer)
    // if (m.function != Benchmark && scoreMax >= 40) return;

    ulong st[25];
    #pragma clang loop unroll(full)
    for (uint i = 0; i < 25; ++i) st[i] = initQ[i];

    // per-thread 32-bit additions (no cross-carry)
    {
        uint lo3 = (uint)(st[3] & 0xFFFFFFFFUL);
        uint hi3 = (uint)(st[3] >> 32);
        lo3 = (uint)(lo3 + (uint)deviceIndex);
        hi3 = (uint)(hi3 + (uint)gid);
        st[3] = ((ulong)hi3 << 32) | (ulong)lo3;

        uint lo4 = (uint)(st[4] & 0xFFFFFFFFUL);
        uint hi4 = (uint)(st[4] >> 32);
        lo4 = (uint)(lo4 + (uint)round);
        st[4] = ((ulong)hi4 << 32) | (ulong)lo4;
    }

    sha3_keccakf(st);

    // H = bytes [12..31] => [st1 bytes 4..7] + st2 + st3 (little-endian)
    uchar H[20];
    ulong a = st[1], b = st[2], c = st[3];
    H[0] = (uchar)((a >> 32) & 0xFF);
    H[1] = (uchar)((a >> 40) & 0xFF);
    H[2] = (uchar)((a >> 48) & 0xFF);
    H[3] = (uchar)((a >> 56) & 0xFF);
    #pragma clang loop unroll(full)
    for (uint j = 0; j < 8; ++j) H[4  + j] = (uchar)((b >> (8*j)) & 0xFF);
    #pragma clang loop unroll(full)
    for (uint j = 0; j < 8; ++j) H[12 + j] = (uchar)((c >> (8*j)) & 0xFF);

    switch (m.function) {
        case Benchmark:      eradicate2_score_benchmark   (H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
        case ZeroBytes:      eradicate2_score_zerobytes   (H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
        case Matching:       eradicate2_score_matching    (H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
        case Leading:        eradicate2_score_leading     (H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
        case Range:          eradicate2_score_range       (H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
        case Mirror:         eradicate2_score_mirror      (H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
        case Doubles:        eradicate2_score_doubles     (H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
        case LeadingRange:   eradicate2_score_leadingrange(H, pResult, &m, scoreMax, deviceIndex, gid, round, initQ); break;
    }
}
