'use strict'

/**
 * Dependencies
 * @ignore
 */
const { JWA } = require('@trust/jwa')
const fetch = require('node-fetch')
const fs = require('fs')

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
    let cryptoKeyPromise, alg

    // Array of objects/alg strings
    if (Array.isArray(data)) {
      return Promise.all(data.map(item => this.generateKeys(item)))

    // JWA alg string
    } else if (typeof data === 'string' && data !== '') {
      alg = data
      cryptoKeyPromise = JWA.generateKey(alg, { key_ops: ['sign', 'verify'], alg })

    // Key descriptor object
    } else if (typeof data === 'object' && data !== null) {
      let { alg: algorithm, key_ops } = data
      alg = algorithm

      if (!alg) {
        return Promise.reject(new DataError('Valid JWA algorithm required for generateKey'))
      }

      if (!key_ops) {
        data.key_ops = ['sign', 'verify']
      }

      cryptoKeyPromise = JWA.generateKey(alg, data)

    // Invalid input
    } else {
      return Promise.reject(new DataError('Invalid input'))
    }

    return cryptoKeyPromise
      .then(({ privateKey, publicKey }) => [privateKey, publicKey])
      .then(keys => Promise.all(keys.map(key => JWK.fromCryptoKey(alg, key))))
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
   * @todo import encrypted JWKSet
   */
  importKeys (data) {
    if (!data) {
      return Promise.reject(new DataError('Invalid input'))
    }

    // Import Array of JWKs
    if (Array.isArray(data)) {
      return Promise.all(data.map(item => this.importKeys(item)))
    }

    if (typeof data === 'string') {
      // Stringified JWK or JWKSet
      if (data.startsWith('{') || data.startsWith('[')) {
        return Promise.resolve()
          .then(() => JSON.parse(data))
          .then(parsed => this.importKeys(parsed))
          .catch(error => Promise.reject(new DataError('Invalid JSON String')))

      // Import from URL
      } else if (data.startsWith('http')) {
        return fetch(data)
          .then(res => res.json())
          .then(json => this.importKeys(json))
          .catch(error => Promise.reject(new DataError(`Failed to fetch remote JWKSet ${data}`)))

      // Import from File
      } else {
        return Promise.resolve()
          .then(() => fs.readFileSync(data, 'utf8'))
          .then(file => this.importKeys(file))
          .catch(error => Promise.reject(new DataError(`Invalid file path ${data}`)))
      }
    }

    // Import JWKSet Object
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
    let { keys } = this

    // Function predicate
    if (typeof predicate === 'function') {
      return keys.filter(predicate)

    // Object
    } else if (typeof predicate === 'object') {
      return keys.filter(jwk => {
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
    let { keys } = this

    // Function predicate
    if (typeof predicate === 'function') {
      return keys.find(predicate)

    // Object
    } else if (typeof predicate === 'object') {
      return keys.find(jwk => {
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
   *
   * @todo rotate
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
