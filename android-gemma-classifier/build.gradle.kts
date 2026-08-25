plugins {
    id("com.android.library")
    kotlin("android")
}

group = "com.agenthita.sdk"
version = "0.1.0"

android {
    namespace = "com.agenthita.sdk.gemma"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    api(project(":"))
    implementation("com.google.mediapipe:tasks-genai:0.10.22")

    testImplementation(kotlin("test"))
}
