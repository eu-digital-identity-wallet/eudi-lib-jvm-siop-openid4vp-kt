package eu.europa.ec.euidw.openid4vp

interface HttpGet<R> {
    suspend fun get(url: HttpsUrl): Result<R>
}