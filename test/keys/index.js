'use strict'

/**
 * Keys
 * @ignore
 */
const { RSAPrivateJWK, RSAPublicJWK } = require('./RSA')
const { ECPrivateJWK, ECPublicJWK } = require('./EC')
const { A256GCMJWK } = require('./A256GCM')

/**
 * Exports
 * @ignore
 */
module.exports = {
  RSAPrivateJWK,
  RSAPublicJWK,
  ECPrivateJWK,
  ECPublicJWK,
  A256GCMJWK,
}
