'use strict'

/**
 * Dependencies
 * @ignore
 */
const { JWA } = require('@trust/jwa')

/**
 * Module Dependencies
 * @ignore
 */
const JWK = require('./JWK')
const { DataError } = require('./errors')

/**
 * JWKSet
 * @ignore
 */
class JWKSet {

  /**
   * constructor
   *
   * @class
   * JWKSet
   *
   * @param  {(Object|Array)} data
   */
  constructor (data = {}) {
    if (Array.isArray(data)) {
      this.keys = data
    } else {
      Object.assign(this, data)
    }

    if (!this.keys) {
      this.keys = []
    }
  }

  /**
   * generateKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   */
  static generateKeys (data) {
    return Promise.resolve(new JWKSet())
      .then(jwks => jwks.generateKeys(data).then(() => jwks))
  }

  /**
   * importKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   */
  static importKeys (data) {
    return Promise.resolve(new JWKSet())
      .then(jwks => jwks.importKeys(data).then(() => jwks))
  }

  /**
   * generateKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   */
  generateKeys (data) {
    let cryptoKeyPromise

    // Array of objects/alg strings
    if (Array.isArray(data)) {
      return Promise.all(data.map(item => this.generateKeys(item)))

    // JWA alg string
    } else if (typeof data === 'string' && data !== '') {
      cryptoKeyPromise = JWA.generateKey(data, { key_ops: ['sign', 'verify'], alg: data })

    // Key descriptor object
    } else if (typeof data === 'object' && data !== null) {
      let { alg } = data

      if (!alg) {
        throw new DataError('Valid JWA algorithm required for generateKey')
      }

      cryptoKeyPromise = JWA.generateKey(alg, data)

    // Invalid input
    } else {
      return Promise.reject(new DataError('Invalid input'))
    }

    let privateCrypto, publicCrypto
    return cryptoKeyPromise
      .then(({ privateKey, publicKey }) => {
        privateCrypto = privateKey
        publicCrypto = publicKey

        return Promise.all([
          JWA.exportKey('jwk', privateKey),
          JWA.exportKey('jwk', publicKey)
        ])
      })
      .then(([privateKey, publicKey]) => {
        let privateJwk = new JWK(privateKey)
        let publicJwk = new JWK(publicKey)

        Object.defineProperty(privateJwk, 'cryptoKey', { value: privateCrypto, enumerable: false, configurable: false })
        Object.defineProperty(publicJwk, 'cryptoKey', { value: publicCrypto, enumerable: false, configurable: false })

        this.keys.push(privateJwk)
        this.keys.push(publicJwk)

        return {
          privateKey: privateJwk,
          publicKey: publicJwk
        }
      })
      .catch(error => console.error('ERROR', error))
  }

  /**
   * importKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   */
  importKeys (data) {
    return Promise.resolve(this)
  }

  /**
   * filter
   *
   * @param  {(Function|Object)} predicate - Filter function or predicate object
   * @return {Promise}
   */
  filter (predicate) {
    return Promise.resolve(this)
  }

  /**
   * find
   *
   * @param  {(Function|Object)} predicate - Find function or predicate object
   * @return {Promise}
   */
  find (predicate) {
    return Promise.resolve(this)
  }

  /**
   * rotate
   *
   * @param  {(JWK|Array|Object|Function)} keys - jwk, array of jwks, filter predicate object or function.
   * @return {Promise}
   */
  rotate (keys) {
    return Promise.resolve(this)
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = JWKSet
