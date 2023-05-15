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

val ktor_version = "2.3.0"
val presentationExchangeVersion = "1.0-SNAPSHOT"
val nimbusSdkVersion = "10.9"

dependencies {
    api("eu.europa.ec.euidw:presentation-exchange-kt:$presentationExchangeVersion")
    api("com.nimbusds:oauth2-oidc-sdk:$nimbusSdkVersion")
    implementation("com.eygraber:uri-kmp:0.0.11")
    api("io.ktor:ktor-client-core:$ktor_version")
    api("io.ktor:ktor-client-content-negotiation:$ktor_version")
    api("io.ktor:ktor-client-serialization:$ktor_version")
    api("io.ktor:ktor-serialization-kotlinx-json:$ktor_version")
    testImplementation(kotlin("test"))
    testImplementation("io.ktor:ktor-client-okhttp:$ktor_version")
    testImplementation("io.ktor:ktor-server-test-host:$ktor_version")
    testImplementation("io.ktor:ktor-server-content-negotiation:$ktor_version")

}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain{
        languageVersion.set(JavaLanguageVersion.of(17))
        vendor.set(JvmVendorSpec.ADOPTIUM)
    }
}

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
        }
    }
    repositories {

        maven {
            name = "NiscyEudiwPackages"
            url = uri("https://maven.pkg.github.com/niscy-eudiw/siop-openid4vp-kt")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }

        }
    }
}
