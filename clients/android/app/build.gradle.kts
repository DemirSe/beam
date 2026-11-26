plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Production APK stays arm64-only. `-Pbeam.includeX86_64=true` adds x86_64 for
// the GitHub Actions KVM emulator (debug builds only in practice).
val includeX86_64 = providers.gradleProperty("beam.includeX86_64").orNull == "true"
val beamVersionCode = providers.gradleProperty("beam.versionCode").orNull?.toIntOrNull()?.coerceAtLeast(1) ?: 1
val beamVersionName = providers.gradleProperty("beam.versionName").orNull?.takeIf { it.isNotBlank() } ?: "0.1.0"

android {
    namespace = "com.beam.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.beam.android"
        minSdk = 31
        targetSdk = 35
        versionCode = beamVersionCode
        versionName = beamVersionName
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Strip unused AppCompat/Material translations to keep the release APK lean.
        resourceConfigurations += listOf("en")

        ndk {
            abiFilters += listOf("arm64-v8a") + if (includeX86_64) listOf("x86_64") else emptyList()
        }
    }

    signingConfigs {
        getByName("debug") {
            val ciDebugKs = file("${System.getProperty("user.home")}/.android/debug.keystore")
            if (ciDebugKs.exists()) {
                storeFile = ciDebugKs
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
        val ksPath = System.getenv("BEAM_KEYSTORE_PATH")
        if (!ksPath.isNullOrBlank()) {
            val ksPassword = System.getenv("BEAM_KEYSTORE_PASSWORD")
            val ksAlias = System.getenv("BEAM_KEY_ALIAS")
            val ksKeyPassword = System.getenv("BEAM_KEY_PASSWORD")
            if (ksPassword.isNullOrBlank() || ksAlias.isNullOrBlank() || ksKeyPassword.isNullOrBlank()) {
                throw org.gradle.api.GradleException(
                    "Incomplete release signing env: BEAM_KEYSTORE_PATH requires BEAM_KEYSTORE_PASSWORD, BEAM_KEY_ALIAS, and BEAM_KEY_PASSWORD",
                )
            }
            create("release") {
                storeFile = file(ksPath)
                storePassword = ksPassword
                keyAlias = ksAlias
                keyPassword = ksKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val releaseSigning = signingConfigs.findByName("release")
            if (releaseSigning != null) {
                signingConfig = releaseSigning
            } else if (providers.gradleProperty("beam.signReleaseWithDebug").orNull == "true") {
                signingConfig = signingConfigs.getByName("debug")
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        viewBinding = true
        aidl = true
    }

    packaging {
        resources {
            excludes += listOf(
                "DebugProbesKt.bin",
                "META-INF/*.version",
                "META-INF/CHANGES",
                "META-INF/README.md",
                "kotlin-tooling-metadata.json",
            )
        }
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
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    // QR scanner (CameraX 1.4.2+ for 16 KB ELF page alignment + ZXing)
    implementation("androidx.camera:camera-core:1.4.2")
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    implementation("com.google.zxing:core:3.5.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
