package niscy.eudiw.openid4vp

interface HttpGet<R> {
    suspend fun get(url: HttpsUrl): Result<R>
}