fn main() {
    // Compile the C variadic shim for BeaconPrintf.
    // On Windows targets this links via mingw; on non-Windows it still
    // compiles (BOF execution is a no-op on Linux but the tests run).
    cc::Build::new().file("csrc/bof_printf.c").warnings(true).compile("bof_printf");
}
