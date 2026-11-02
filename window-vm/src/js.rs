//! Facade mirroring cfsolve `src/js.rs`: the JS-support surface shared across the crate —
//! numeric ops for the hash ports and value helpers over boa. cfsolve's version wraps swc's
//! parser; ours wraps boa (deviation 1, DESIGN.md §9.1 — the reCAPTCHA capture is a full
//! runnable program, not a register machine to disassemble).

/// Signed-32 semantics of the JS `| 0` / `>>> 0` family, for the hash ports.
pub fn to_signed32(v: u32) -> i32 {
    if v >= 0x8000_0000 {
        (v as i64 - 0x1_0000_0000) as i32
    } else {
        v as i32
    }
}
