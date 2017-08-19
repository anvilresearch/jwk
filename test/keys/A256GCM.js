'use strict'

/**
 * Secret JWK
 */
const A256GCMJWK = {
  alg: 'A256GCM',
  ext: true,
  k: '5hPNmHk7tTFZxLiBEmenM58ZF0dup1Z9YHmDhU26_t4',
  key_ops: ['encrypt','decrypt','wrapKey','unwrapKey'],
  kty: 'oct',
  kid: '1'
}

/**
 * Exports
 * @ignore
 */
module.exports = {
  A256GCMJWK
}
