object Meta {
    const val orgUrl = "https://github.com/eu-digital-identity-wallet"
    const val projectDescription = "SIOP & OpenId4VP wallet role library"
    const val projectBaseUrl = "https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt"
    const val projectGitUrl = "scm:git:git@github.com:eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt.git"
    const val projectSshUrl = "scm:git:ssh://github.com:eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt.git"
}

plugins {
    id("org.sonarqube") version "4.0.0.2929"
    kotlin("jvm") version "1.8.22"
    kotlin("plugin.serialization") version "1.8.21"
    id("com.diffplug.spotless") version "6.19.0"
    `java-library`
    `maven-publish`
    signing
}

extra["isReleaseVersion"] = !version.toString().endsWith("SNAPSHOT")

repositories {
    mavenCentral()
    mavenLocal()
    maven {
        url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
        mavenContent { snapshotsOnly() }
    }
}

val ktorVersion = "2.3.0"
val presentationExchangeVersion = "0.1.0-SNAPSHOT"
val nimbusSdkVersion = "10.9.1"

dependencies {
    api("eu.europa.ec.eudi:eudi-lib-jvm-presentation-exchange-kt:$presentationExchangeVersion")
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

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.jar {
    manifest {
        attributes(
            mapOf(
                "Implementation-Title" to project.name,
                "Implementation-Version" to project.version,
            ),
        )
    }
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
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
            pom {
                name.set(project.name)
                description.set(Meta.projectDescription)
                url.set(Meta.projectBaseUrl)
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                scm {
                    connection.set(Meta.projectGitUrl)
                    developerConnection.set(Meta.projectSshUrl)
                    url.set(Meta.projectBaseUrl)
                }
                issueManagement {
                    system.set("github")
                    url.set(Meta.projectBaseUrl + "/issues")
                }
                ciManagement {
                    system.set("github")
                    url.set(Meta.projectBaseUrl + "/actions")
                }
                developers {
                    organization {
                        url.set(Meta.orgUrl)
                    }
                }
            }
        }
    }
    repositories {

        val sonaUri =
            if ((extra["isReleaseVersion"]) as Boolean) {
                "https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/"
            } else {
                "https://s01.oss.sonatype.org/content/repositories/snapshots/"
            }

        maven {
            name = "sonatype"
            url = uri(sonaUri)
            credentials(PasswordCredentials::class)
        }
    }
}

signing {
    setRequired({
        (project.extra["isReleaseVersion"] as Boolean) && gradle.taskGraph.hasTask("publish")
    })
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["library"])
}
