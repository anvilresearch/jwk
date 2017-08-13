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
      let { alg, key_ops } = data

      if (!alg) {
        throw new DataError('Valid JWA algorithm required for generateKey')
      }

      if (!key_ops) {
        data.key_ops = ['sign', 'verify']
      }

      cryptoKeyPromise = JWA.generateKey(alg, data)

    // Invalid input
    } else {
      return Promise.reject(new DataError('Invalid input'))
    }

    let privateCrypto, publicCrypto
    return cryptoKeyPromise
      .then(({ privateKey, publicKey }) => [privateKey, publicKey])
      .then(keys => Promise.all(keys.map(key => JWK.fromCryptoKey(key))))
      .then(keys => {
        this.keys = this.keys.concat(keys)
        return keys
      })
  }

  /**
   * importKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   *
   * @todo import from file
   * @todo import from url
   * @todo import encrypted JWKSet
   */
  importKeys (data) {
    if (!data) {
      return Promise.reject(new DataError('Invalid input'))
    }

    if (Array.isArray(data)) {
      return Promise.all(data.map(item => this.importKeys(item)))
    }

    if (typeof data === 'object' && data !== null && data.keys) {
      // Assign non-keys property to the JWKSet
      let meta = Object.keys(data)
        .filter(key => key !== 'keys')
        .reduce((state, current) => state[current] = data[current], {})
      Object.assign(this, meta)

      // Import keys
      return this.importKeys(data.keys)
    }

    return JWK.importKey(data).then(jwk => {
      this.keys.push(jwk)
      return jwk
    })
  }

  /**
   * filter
   *
   * @param  {(Function|Object)} predicate - Filter function or predicate object
   * @return {Promise}
   */
  filter (predicate) {
    // Function predicate
    if (typeof predicate === 'function') {
      return this.keys.filter(predicate)

    // Object
    } else if (typeof predicate === 'object') {
      return this.keys.filter(jwk => {
        return Object.keys(predicate)
          .map(key => jwk[key] === predicate[key])
          .reduce((state, current) => state && current, true)
      })

    // Invalid input
    } else {
      return Promise.reject(new OperationError('Invalid predicate'))
    }
  }

  /**
   * find
   *
   * @param  {(Function|Object)} predicate - Find function or predicate object
   * @return {Promise}
   */
  find (predicate) {
    // Function predicate
    if (typeof predicate === 'function') {
      return this.keys.find(predicate)

    // Object
    } else if (typeof predicate === 'object') {
      return this.keys.find(jwk => {
        return Object.keys(predicate)
          .map(key => jwk[key] === predicate[key])
          .reduce((state, current) => state && current, true)
      })

    // Invalid input
    } else {
      return Promise.reject(new OperationError('Invalid predicate'))
    }
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

  /**
   * exportKeys
   *
   * @param  {JWK} [kek] - optional encryption key
   * @return {String} JSON String
   *
   * @todo encryption
   */
  exportKeys (kek) {
    return JSON.stringify(this, null, 2)
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = JWKSet
