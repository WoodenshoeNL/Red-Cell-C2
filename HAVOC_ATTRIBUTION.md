# Havoc C2 Attribution

This project is a Rust rewrite of the [Havoc C2 framework](https://github.com/HavocFramework/Havoc)
by [@C5pider](https://github.com/C5pider), licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).

Red Cell C2 maintains Demon agent protocol compatibility and includes the
following files that originate from or are derived from the Havoc project:

## Included Havoc-derived files

| Path | Origin | Description |
|------|--------|-------------|
| `agent/demon/` | `Havoc/payloads/Demon/` | Demon agent C/ASM source (frozen, unmodified copy) |
| `agent/demon/payloads/Shellcode.x64.bin` | `Havoc/payloads/Shellcode.x64.bin` | Pre-built x64 shellcode loader template |
| `agent/demon/payloads/Shellcode.x86.bin` | `Havoc/payloads/Shellcode.x86.bin` | Pre-built x86 shellcode loader template |
| `agent/demon/payloads/DllLdr.x64.bin` | `Havoc/payloads/DllLdr.x64.bin` | Pre-built x64 DLL loader for Raw Shellcode format |
| `agent/archon/` | Fork of `Havoc/payloads/Demon/` | Archon agent — initially identical to Demon, diverging with enhancements |

## License

All files listed above are licensed under **GPLv3**, matching both the original
Havoc project and this repository's license.

## Havoc Credits

The original Havoc project credits the following contributors:

- [Austin Hudson (@ilove2pwn_)](https://twitter.com/ilove2pwn_) — code and ideas; Foliage sleep obfuscation technique
- [Bobby Cooke (@0xBoku)](https://twitter.com/0xBoku) — techniques
- [Codex (@codex_tf2)](https://twitter.com/codex_tf2) — contributions and testing
- [Robert Musser (@r_o_b_e_r_t_1)](https://twitter.com/r_o_b_e_r_t_1) — contributions, testing, Docker support
- [Adam Svoboda (@adamsvoboda)](https://twitter.com/adamsvoboda) — contributions, testing, wiki
- [trickster0 (@trickster012)](https://twitter.com/trickster012) — contributions and testing
- [Raul / theg3ntl3m4n (@theg3ntl3m4n)](https://twitter.com/theg3ntl3m4n) — contributions and testing
- [Zach Fleming (@The___Undergrad)](https://twitter.com/The___Undergrad) — contributions and testing
- [Shawn / anthemtotheego (@anthemtotheego)](https://twitter.com/anthemtotheego) — contributions and testing
