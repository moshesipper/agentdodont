import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.aos.launcher"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.aos.launcher"
        minSdk = 30 // covers the S22 (Android 16) and the A12 (Android 13)
        targetSdk = 34
        // One version for the whole project: the Python package's (agentdodont/__init__.py).
        val version = Regex("__version__ = \"(\\d+)\\.(\\d+)\\.(\\d+)\"")
            .find(rootProject.file("../agentdodont/__init__.py").readText())!!.groupValues
        versionName = "${version[1]}.${version[2]}.${version[3]}"
        versionCode = version[1].toInt() * 10000 + version[2].toInt() * 100 + version[3].toInt()

        // The app reaches Claude only through the laptop relay (`python -m agentdodont relay`), which
        // holds the API key. Nothing secret is compiled in: the build never reads anthropic.apiKey, and
        // the relay writes the device token into the app's private storage at runtime (USB) or the
        // phone gets one by pairing (Wi-Fi). Only the USB relay address comes from local.properties.
        val localProps = Properties().apply {
            val f = rootProject.file("local.properties")
            if (f.exists()) f.inputStream().use { load(it) }
        }
        val relayUrl = localProps.getProperty("aos.relayUrl") ?: "http://127.0.0.1:8787"
        // A resource, not a BuildConfig constant: Kotlin inlines Java constants at compile time, so an
        // incremental build could keep a stale value. Resources are read at runtime.
        resValue("string", "relay_url", relayUrl.replace("\"", ""))
    }

    // Release builds are signed only when the key is supplied from outside the repository (the
    // release workflow gets it from GitHub secrets). Every published APK must use the same key,
    // or phones refuse the update.
    val keystore = System.getenv("AGENTDODONT_KEYSTORE")
    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("AGENTDODONT_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("AGENTDODONT_KEY_ALIAS") ?: "agentdodont"
                keyPassword = System.getenv("AGENTDODONT_KEYSTORE_PASSWORD")
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            if (keystore != null) signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        resources.excludes += setOf("META-INF/DEPENDENCIES", "META-INF/LICENSE*", "META-INF/NOTICE*", "META-INF/*.kotlin_module")
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.04.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.8.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("com.anthropic:anthropic-java:3.3.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    testImplementation("junit:junit:4.13.2")
}
