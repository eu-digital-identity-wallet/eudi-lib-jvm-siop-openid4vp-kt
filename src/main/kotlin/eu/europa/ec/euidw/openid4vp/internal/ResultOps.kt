package eu.europa.ec.euidw.openid4vp.internal

//
// Helper methods
//
internal fun <T> T.success(): Result<T> = Result.success(this)
internal fun <T> Result<T>.mapError(map: (Throwable) -> Throwable): Result<T> =
    fold(onSuccess = { it.success() }, onFailure = { Result.failure(map(it)) })
