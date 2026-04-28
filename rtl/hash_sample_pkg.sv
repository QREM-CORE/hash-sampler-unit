package hash_sample_pkg;
    // Import specific Keccak/Global types to avoid DWIDTH collision
    import keccak_pkg::XOF_LEN_WIDTH;
    import keccak_pkg::keccak_mode;
    import keccak_pkg::SHA3_256;
    import keccak_pkg::SHA3_512;
    import keccak_pkg::SHAKE128;
    import keccak_pkg::SHAKE256;

    import qrem_global_pkg::hs_mode_t;

    // Export them so modules importing THIS package also get Keccak types
    export keccak_pkg::XOF_LEN_WIDTH;
    export keccak_pkg::keccak_mode;
    export keccak_pkg::SHA3_256;
    export keccak_pkg::SHA3_512;
    export keccak_pkg::SHAKE128;
    export keccak_pkg::SHAKE256;

    // Export HSU global modes
    export qrem_global_pkg::hs_mode_t;

endpackage : hash_sample_pkg
