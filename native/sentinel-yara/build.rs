fn main() {
    println!("cargo:rerun-if-changed=jni/bridge.c");
    let mut build = cc::Build::new();
    build
        .file("jni/bridge.c")
        .warnings(true)
        .extra_warnings(true);
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "android" {
        let ndk = std::env::var("ANDROID_NDK_HOME").expect("pinned Docker NDK required");
        build.include(format!(
            "{ndk}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include"
        ));
    } else {
        build.include("jni/host");
    }
    build.compile("sentinel_jni_bridge");
}
