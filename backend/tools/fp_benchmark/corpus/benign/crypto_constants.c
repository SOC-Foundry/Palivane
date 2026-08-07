/* SHA-256 round constants (FIPS 180-4) — public math, not secrets. */
static const uint32_t K[8] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
};
static const char *INIT_HASH = "6a09e667bb67ae853c6ef372a54ff53a";
