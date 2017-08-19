'use strict'

/**
 * Dependencies
 * @ignore
 */
const { JWA } = require('@trust/jwa')
const crypto = require('@trust/webcrypto')
const fetch = require('node-fetch')
const sift = require('sift')
const fs = require('fs')

/**
 * Module Dependencies
 * @ignore
 */
const JWK = require('./JWK')
const { DataError, OperationError } = require('./errors')

/**
 * Random KID Generator
 */
/* istanbul ignore */
function random (byteLen) {
  let value = crypto.getRandomValues(new Uint8Array(byteLen))
  return Buffer.from(value).toString('hex')
}

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

      // TODO this should not default to ['sign', 'verify'] and causes problems for generateing symmetric keys
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
      .then(keys => {
        let kid = random(8)
        return Promise.all(keys.map(key => JWK.fromCryptoKey(key, { alg, kid })))
      })
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
        .reduce((state, current) => {
          state[current] = data[current]
          return state
        }, {})
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
      return sift(predicate, keys)

    // Invalid input
    } else {
      throw new OperationError('Invalid predicate')
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
      let sifter = sift(predicate)
      return keys.find(sifter)

    // Invalid input
    } else {
      throw new OperationError('Invalid predicate')
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
    return JSON.stringify(this)
  }

  /**
   * publicJwks
   *
   * @return {String} Publishable JSON JWKSet
   *
   * @todo memoise this
   */
  get publicJwks () {
    let keys = this.filter(key => key.cryptoKey.type === 'public')
    let metadata = Object.keys(this)
      .filter(field => field !== 'keys')
      .reduce((state, current) => {
        state[current] = this[current]
        return state
      }, {})
    let publish = Object.assign({}, metadata, { keys })

    return JSON.stringify(publish, null, 2)
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = JWKSet
