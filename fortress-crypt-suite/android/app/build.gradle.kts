plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.fortress.crypt"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.fortress.crypt"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "2.0.0"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Compose
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")

    // Bouncy Castle — Camellia, scrypt, SHA3, ChaCha20, ML-KEM
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")

    // Argon2
    implementation("com.lambdapioneer.argon2kt:argon2kt:1.6.0")

    // Biometric
    implementation("androidx.biometric:biometric:1.1.0")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // Security (EncryptedSharedPreferences, Keystore)
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // File provider for sharing
    implementation("androidx.core:core-ktx:1.15.0")
}
