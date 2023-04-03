package eu.europa.ec.euidw.openid4vp

//
// Helper methods
//
internal fun <T> T.success(): Result<T> = Result.success(this)
