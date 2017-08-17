'use strict'

/**
 * Private JWK
 */
const ECPrivateJWK = {
  kty: 'EC',
  crv: 'P-256',
  d: 'V0hmw8nudj1mtr6MadRkXxQEiJP-f3O8wk2E-5n9zic',
  x: '73a4dOjchLnvNZQClbAqhNGWTv2edQKayJ5OqU9xdmI',
  y: 'CmMhgetVMliOoukeVhXrYsNGxLDKuEnzlWio2LsDwug',
  key_ops: [ 'sign' ],
  ext: true,
  alg: 'ES256'
}

/**
 * Public JWK
 */
const ECPublicJWK = {
  kty: 'EC',
  crv: 'P-256',
  x: '73a4dOjchLnvNZQClbAqhNGWTv2edQKayJ5OqU9xdmI',
  y: 'CmMhgetVMliOoukeVhXrYsNGxLDKuEnzlWio2LsDwug',
  key_ops: [ 'verify' ],
  ext: true,
  alg: 'ES256'
}

/**
 * Exports
 * @ignore
 */
module.exports = {
  ECPrivateJWK,
  ECPublicJWK
}
