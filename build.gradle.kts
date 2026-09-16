plugins {
    kotlin("multiplatform") version "2.2.10"
    id("com.android.library") version "9.1.0"
}

group = "com.agenthita.sdk"
version = "0.1.0"

kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    // Full iOS device + simulator matrix so the SDK can be consumed from
    // Xcode on Apple Silicon (iosSimulatorArm64), Intel Macs (iosX64), and
    // real devices (iosArm64). Built here structurally; full compile/link
    // verification requires a machine with Xcode installed, not just the
    // Command Line Tools.
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "HitaSafetySDK"
            isStatic = true
        }
    }

    // The default hierarchy template already creates and wires the intermediate
    // "iosMain" source set (dependsOn commonMain, depended on by iosX64Main/
    // iosArm64Main/iosSimulatorArm64Main) automatically for this exact target
    // set — no manual dependsOn wiring needed or wanted here.
    sourceSets {
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val androidUnitTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}

android {
    namespace = "com.agenthita.sdk.detection"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
