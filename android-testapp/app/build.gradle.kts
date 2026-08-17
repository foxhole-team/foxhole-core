plugins {
    id("com.android.application")
}

android {
    namespace = "com.foxhole.coretest"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.foxhole.coretest"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1"
        // The shipped set, and only it. x86_64 was here for the Android Studio
        // emulator, but scripts/android-build.sh no longer produces it by
        // default, so listing it here would package an ABI with no library
        // behind it. An emulator session builds it deliberately —
        // FOXCORE_ANDROID_ABIS=x86_64 scripts/android-build.sh — and adds it
        // back here for as long as that session lasts.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
    }
}
