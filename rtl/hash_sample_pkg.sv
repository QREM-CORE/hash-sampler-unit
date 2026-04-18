package hash_sample_pkg;
    // Import Keccak types
    import keccak_pkg::*;
    // Export them so modules importing THIS package also get Keccak types
    export keccak_pkg::XOF_LEN_WIDTH;
    export keccak_pkg::keccak_mode;
    export keccak_pkg::SHA3_256;
    export keccak_pkg::SHA3_512;
    export keccak_pkg::SHAKE128;
    export keccak_pkg::SHAKE256;

    // Enumerated type for the Hash-Sampler Unit modes
    // logic [2:0] provides enough width for the 5 defined modes.
    typedef enum logic [2:0] {
        MODE_SAMPLE_NTT    = 3'd0, // Op: SHAKE128  | Sampler: Rejection | Target: Matrix A
        MODE_SAMPLE_CBD    = 3'd1, // Op: SHAKE256  | Sampler: CBD       | Target: s, e, e1, e2
        MODE_HASH_SHA3_256 = 3'd2, // Op: SHA3-256  | Sampler: Bypass    | Target: H(pk), H(m), H(c)
        MODE_HASH_SHA3_512 = 3'd3, // Op: SHA3-512  | Sampler: Bypass    | Target: G(d), G(m, h)
        MODE_HASH_SHAKE256 = 3'd4  // Op: SHAKE256  | Sampler: Bypass    | Target: J(z, c)
    } hs_mode_t;

    // AXI4-Stream Widths
    localparam int HSU_IN_DWIDTH = 64;
    localparam int HSU_IN_KEEP_WIDTH = HSU_IN_DWIDTH / 8;

endpackage : hash_sample_pkg
