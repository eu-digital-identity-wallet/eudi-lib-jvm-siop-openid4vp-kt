package niscy.eudiw.openid4vp

//
// Helper methods
//
internal fun <T> T.success(): Result<T> = Result.success(this)
