plugins {
    kotlin("jvm") version "1.8.21"
    kotlin("plugin.serialization") version "1.8.21"
    id("com.diffplug.spotless") version "6.19.0"
    `java-library`
    `maven-publish`
}

group = "eu.europa.ec.euidw"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        name = "EUDIWalletSnapshots"
        val dependenciesRepoUrl = System.getenv("DEP_MVN_REPO") ?: "https://maven.pkg.github.com/eu-digital-identity-wallet/*"
        url = uri(dependenciesRepoUrl)
        credentials {
            username = System.getenv("GH_PKG_USER")
            password = System.getenv("GH_PKG_TOKEN")
        }
        mavenContent {
            snapshotsOnly()
        }
    }
    mavenLocal()
}

val ktorVersion = "2.3.0"
val presentationExchangeVersion = "1.0-SNAPSHOT"
val nimbusSdkVersion = "10.9.1"

dependencies {
    api("eu.europa.ec.euidw:presentation-exchange-kt:$presentationExchangeVersion")
    api("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    implementation("com.eygraber:uri-kmp:0.0.11")
    api("io.ktor:ktor-client-core:$ktorVersion")
    api("io.ktor:ktor-client-content-negotiation:$ktorVersion")
    api("io.ktor:ktor-client-serialization:$ktorVersion")
    api("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")
    testImplementation(kotlin("test"))
    testImplementation("io.ktor:ktor-client-okhttp:$ktorVersion")
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testImplementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
        vendor.set(JvmVendorSpec.ADOPTIUM)
    }
}

val ktlintVersion = "0.49.1"
spotless {
    kotlin {
        ktlint(ktlintVersion)
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
        }
    }
    val publishMvnRepo = System.getenv("PUBLISH_MVN_REPO")?.let { uri(it) }
    if (null != publishMvnRepo) {
        repositories {

            maven {
                name = "EUDIWalletSnapshots"
                url = uri(publishMvnRepo)
                credentials {
                    username = System.getenv("GITHUB_ACTOR")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    } else {
        println("Warning: PUBLISH_MVN_REPO undefined. Won't publish")
    }
}
