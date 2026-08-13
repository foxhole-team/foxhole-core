fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // `#[link(name = "android")]` on the extern block is not enough: a cdylib may
    // keep undefined symbols, so the link succeeds even when `--as-needed` drops
    // the DT_NEEDED entry for libandroid. The failure then only appears on device,
    // as `dlopen: cannot locate symbol "android_setsocknetwork"`.
    //
    // Android's linker enables `--as-needed`, and a cdylib may retain unresolved
    // dynamic symbols. Merely appending `-landroid` therefore still lets the
    // dependency disappear. Disable as-needed for this explicit platform
    // dependency; the ELF gate verifies the resulting DT_NEEDED entry.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-arg=-Wl,--no-as-needed");
        println!("cargo:rustc-link-arg=-landroid");
        // liblog, for `__android_log_write` in `logcat.rs`. Same reasoning as
        // libandroid above: the explicit link arg is what keeps --as-needed
        // from dropping it and turning a missing symbol into a device-only
        // failure.
        println!("cargo:rustc-link-arg=-llog");
        println!("cargo:rustc-link-arg=-Wl,-z,max-page-size=16384");
        println!("cargo:rustc-link-arg=-Wl,-z,common-page-size=16384");
    }
}
