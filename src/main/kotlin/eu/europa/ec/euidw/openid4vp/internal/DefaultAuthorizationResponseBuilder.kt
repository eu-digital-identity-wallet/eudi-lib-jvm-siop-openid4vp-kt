package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.ThumbprintUtils
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import eu.europa.ec.euidw.openid4vp.*
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*

internal class DefaultAuthorizationResponseBuilder(
    val walletConfig: WalletOpenId4VPConfig
) : AuthorizationResponseBuilder {

    override suspend fun buildResponse(
        requestObject: ResolvedRequestObject,
        consensus: Consensus
    ): AuthorizationResponse {
        val responseData = buildResponseData(requestObject, consensus)
        return when (val responseMode = requestObject.responseMode) {
            is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(responseMode.responseURI, requestObject.state, responseData)
            is ResponseMode.DirectPostJwt -> TODO("Not yet implemented")
            is ResponseMode.Fragment -> TODO("Not yet implemented")
            is ResponseMode.Query -> TODO("Not yet implemented")
        }
    }

    private fun buildResponseData(
        resolvedRequest: ResolvedRequestObject,
        consensus: Consensus
    ): AuthorizationResponseData {

        return when (consensus) {
            is Consensus.PositiveConsensus -> {
                when (resolvedRequest) {
                    is ResolvedRequestObject.IdTokenRequestObject -> buildIDTokenResponseData(resolvedRequest,consensus)
                    is ResolvedRequestObject.VpTokenRequestObject -> buildVPTokenResponseData(resolvedRequest,consensus)
                    is ResolvedRequestObject.IdAndVPTokenRequestObject -> buildIDAndVPTokenResponseData(resolvedRequest,consensus)
                }
            }

            else -> AuthorizationResponseData.NoConsensusResponseData("User has not approved request")
        }

    }

    private fun buildIDTokenResponseData(
        request: ResolvedRequestObject.IdTokenRequestObject,
        consensus: Consensus.PositiveConsensus
    ): AuthorizationResponseData.IdTokenResponseData {
        return when (consensus) {
            is Consensus.PositiveConsensus.IdTokenConsensus -> AuthorizationResponseData.IdTokenResponseData(buildIdToken(request))
            else -> throw IllegalStateException("")
        }
    }

    private fun buildVPTokenResponseData(
        request: ResolvedRequestObject.VpTokenRequestObject,
        consensus: Consensus.PositiveConsensus
    ): AuthorizationResponseData.VPTokenResponseData {
        TODO("Not yet implemented")
    }

    private fun buildIDAndVPTokenResponseData(
        request: ResolvedRequestObject.IdAndVPTokenRequestObject,
        consensus: Consensus.PositiveConsensus
    ): AuthorizationResponseData.IdAndVPTokenResponseData {
        TODO("Not yet implemented")
    }


    private fun buildIdToken(request: ResolvedRequestObject.IdTokenRequestObject) : JWT {

        fun sign(claimSet: IDTokenClaimsSet): Result<JWT> = runCatching {
            val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(walletConfig.rsaJWK.keyID).build()
            val signedJWT = SignedJWT(header, claimSet.toJWTClaimsSet())
            signedJWT.sign(RSASSASigner(walletConfig.rsaJWK))
            signedJWT
        }

        fun buildJWKThumbprint() : String =
            ThumbprintUtils.compute("SHA-256", walletConfig.rsaJWK).toJSONString()

        fun buildIssuerClaim() : String =
            when (walletConfig.preferredSubjectSyntaxType) {
                is SubjectSyntaxType.JWKThumbprint -> buildJWKThumbprint()
                is SubjectSyntaxType.DecentralizedIdentifier -> walletConfig.decentralizedIdentifier
            }

        fun computeTokenDates() : Pair<Date, Date> {
            val now = LocalDateTime.now()
            val iat = Date.from(now.atZone(ZoneId.systemDefault()).toInstant())
            val expLocalDate = now.plusMinutes(walletConfig.idTokenTTL.toMinutes())
            val exp = Date.from(expLocalDate.atZone(ZoneId.systemDefault()).toInstant())
            return iat to exp
        }

        val subjectJwk = JWKSet(walletConfig.rsaJWK).toPublicJWKSet()

        val claimSet = with(JWTClaimsSet.Builder()) {
            issuer( buildIssuerClaim() )
            subject( buildIssuerClaim() ) // By SIOPv2 draft 12 issuer = subject
            audience( request.clientId )
            val (iat, exp) = computeTokenDates()
            issueTime(iat)
            expirationTime(exp)
            claim("sub_jwk", subjectJwk.toJSONObject())
            claim("email", walletConfig.holderEmail)
            claim("name", walletConfig.holderName)
            build()
        }

        return sign(IDTokenClaimsSet(claimSet)).getOrThrow()
    }
}