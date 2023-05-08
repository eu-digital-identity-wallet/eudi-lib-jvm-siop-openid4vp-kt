plugins {
    kotlin("jvm") version "1.8.21"
    kotlin("plugin.serialization") version "1.8.21"
    `java-library`
    `maven-publish`
}

group = "eu.europa.ec.euidw"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        name = "NiscyEudiwPackages"
        url = uri("https://maven.pkg.github.com/niscy-eudiw/*")
        credentials {
            username = System.getenv("GH_PKG_USER")
            password = System.getenv("GH_PKG_TOKEN")
        }
        mavenContent{
            snapshotsOnly()
        }
    }
    mavenLocal()
}

val ktor_version = "2.2.4"
val presentationExchangeVersion = "1.0-SNAPSHOT"
val nimbusSdkVersion = "10.8"

dependencies {
    implementation("eu.europa.ec.euidw:presentation-exchange-kt:$presentationExchangeVersion")
    implementation("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    implementation("com.eygraber:uri-kmp:0.0.11")
    api("io.ktor:ktor-client-core:$ktor_version")
    api("io.ktor:ktor-client-content-negotiation:$ktor_version")
    api("io.ktor:ktor-client-serialization:$ktor_version")
    api("io.ktor:ktor-client-okhttp:$ktor_version")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

