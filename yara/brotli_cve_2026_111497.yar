/*
   YARA rules for CVE-2026-111497 (Broccoli2Shell / Node2Shell / HTTP2Shell):
   out-of-bounds write in the Google Brotli decoder 1.0.3 - 1.2.0.

   The fix (google/brotli 0ed4268, released in 1.0.10, 1.1.1 and 1.2.1) added
   the decoder error code BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH (-17). Its
   name is compiled into BrotliDecoderErrorString()'s table, which is kept in
   shared libraries and in most binaries that bundle Brotli (Node.js, Bun,
   Python wheels, ...). So:

     error table present, BLOCK_SWITCH entry absent  -> vulnerable decoder
     error table present, BLOCK_SWITCH entry present -> fixed decoder

   1.1.x / 1.2.x store the names with a prefix ("_ERROR_FORMAT_BLOCK_SWITCH"),
   1.0.x stores bare names ("BLOCK_SWITCH"). Distro backports that cherry-pick
   the fix (e.g. Ubuntu libbrotli1 1.1.0-2ubuntu0.1) are recognised as fixed
   even though their version string did not change. The strings are plain
   text, so the rules work for every CPU architecture.

   Not covered: stripped static builds where the linker dropped the error
   table (Brotli_Present_Patch_State_Unknown flags these), pure Go/Rust/Java
   reimplementations, and compressed archives (jars).

   Source: https://github.com/depuschm/brotli-k8s-scan  License: MIT
*/

rule Brotli_Decoder_Vulnerable_CVE_2026_111497
{
    meta:
        description = "Brotli decoder without the CVE-2026-111497 fix (1.0.3-1.2.0)"
        cve = "CVE-2026-111497"
        severity = "critical"
        reference = "https://github.com/google/brotli/releases/tag/v1.2.1"
        author = "brotli-k8s-scan"
    strings:
        $nibble_11 = "_ERROR_FORMAT_EXUBERANT_NIBBLE"
        $fix_11    = "_ERROR_FORMAT_BLOCK_SWITCH"
        $nibble_10 = "\x00EXUBERANT_NIBBLE\x00"
        $fix_10    = "\x00BLOCK_SWITCH\x00"
    condition:
        ($nibble_11 and not $fix_11) or
        (not $nibble_11 and $nibble_10 and not $fix_10)
}

rule Brotli_Decoder_Patched_CVE_2026_111497
{
    meta:
        description = "Brotli decoder that contains the CVE-2026-111497 fix"
        cve = "CVE-2026-111497"
        severity = "info"
        author = "brotli-k8s-scan"
    strings:
        $nibble_11 = "_ERROR_FORMAT_EXUBERANT_NIBBLE"
        $fix_11    = "_ERROR_FORMAT_BLOCK_SWITCH"
        $nibble_10 = "\x00EXUBERANT_NIBBLE\x00"
        $fix_10    = "\x00BLOCK_SWITCH\x00"
    condition:
        ($nibble_11 and $fix_11) or
        (not $nibble_11 and $nibble_10 and $fix_10)
}

rule Brotli_Present_Patch_State_Unknown
{
    meta:
        description = "Brotli code compiled in (static dictionary) but no decoder error table: patch state unknown"
        cve = "CVE-2026-111497"
        severity = "medium"
        author = "brotli-k8s-scan"
    strings:
        $dict      = "timedownlifeleftback"
        $nibble_11 = "_ERROR_FORMAT_EXUBERANT_NIBBLE"
        $nibble_10 = "\x00EXUBERANT_NIBBLE\x00"
    condition:
        // Also matches libbrotlicommon / libbrotlienc and encoder-only builds,
        // which carry the dictionary but no decoder: check those by hand.
        $dict and not $nibble_11 and not $nibble_10
}
