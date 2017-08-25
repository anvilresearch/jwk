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
 * JWKSet
 * @ignore
 */
class JWKSet {

  /**
   * constructor
   *
   * @class JWKSet
   *
   * @description
   * JSON Web Key Set ([IETF RFC7517 Section 5.](https://tools.ietf.org/html/rfc7517#section-5))
   *
   * @param  {(Object|Array)} [data]
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
   * @description
   * Instantiate a new JWKSet and generate one or many JWK keypairs and secret keys.
   *
   * @example <caption>Simple RSA keypair</caption>
   * JWKSet.generateKeys('RS256')
   *   .then(console.log)
   * // => { keys: [
   * //      { d: '...',
   * //        kty: 'RSA',
   * //        alg: 'RS256',
   * //        kid: 'abcd',
   * //        ... },
   * //      { kty: 'RSA',
   * //        alg: 'RS256',
   * //        kid: 'abcd',
   * //        ... }
   * //    ] }
   *
   * @example <caption>Multiple keypairs</caption>
   * JWKSet.generateKeys(['RS256', 'ES256'])
   *   .then(console.log)
   * // => { keys: [
   * //      { ..., kty: 'RSA', alg: 'RS256' },
   * //      { ..., kty: 'RSA', alg: 'RS256' },
   * //      { ..., kty: 'EC', alg: 'ES256' },
   * //      { ..., kty: 'EC', alg: 'ES256' }] }
   *
   * @example <caption>Object descriptor RSA keypair</caption>
   * let keyDescriptor = {
   *   alg: 'RS256',
   *   kid: 'custom',
   *   modulusLength: 1024
   * }
   *
   * JWKSet.generateKeys(keyDescriptor)
   *   .then(console.log)
   * // => { keys: [
   * //      { ..., alg: 'RS256', kid: 'custom' },
   * //      { ..., alg: 'RS256', kid: 'custom' }] }
   *
   * @example <caption>Mixed input, multiple keypairs</caption>
   * let keyDescriptor = {
   *   alg: 'RS512',
   *   modulusLength: 1024
   * }
   *
   * JWKSet.generateKeys([keyDescriptor, 'ES256'])
   *   .then(console.log)
   * // => { keys: [
   * //      { ..., kty: 'RSA', alg: 'RS512' },
   * //      { ..., kty: 'RSA', alg: 'RS512' },
   * //      { ..., kty: 'EC', alg: 'ES256' },
   * //      { ..., kty: 'EC', alg: 'ES256' }] }
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise.<JWKSet>} A promise that resolves a new JWKSet containing the generated key pairs.
   */
  static generateKeys (data) {
    return Promise.resolve(new JWKSet())
      .then(jwks => jwks.generateKeys(data).then(() => jwks))
  }

  /**
   * importKeys
   *
   * @description
   * Instantiate a new JWKSet and import keys from JSON string, JS object, remote URL or file path.
   *
   * @example <caption>Import keys from JSON string</caption>
   * let jsonJwkSet = '{"meta":"abcd","keys":[...]}'
   *
   * JWKSet.importKeys(jsonJwkSet)
   *   .then(console.log)
   * // => { meta: 'abcd', keys: [...] }
   *
   * @example <caption>Import keys from object</caption>
   * let jwkSet = {
   *   meta: 'abcd',
   *   keys: [...]
   * }
   *
   * JWKSet.importKeys(jwkSet)
   *   .then(console.log)
   * // => { meta: 'abcd', keys: [...] }
   *
   * @example <caption>Import keys from URL</caption>
   * let jwkSetUrl = 'https://idp.example.com/jwks'
   *
   * JWKSet.importKeys(jwkSetUrl)
   *   .then(console.log)
   * //
   * // HTTP/1.1 200 OK
   * // Content-Type: application/json
   * //
   * // {"meta":"abcd","keys":[...]}
   * //
   * // => { meta: 'abcd',
   * //      keys: [...] }
   *
   * @example <caption>Import keys from file path</caption>
   * let jwkSetPath = './path/to/my/file.json'
   *
   * JWKSet.importKeys(jwkSetPath)
   *   .then(console.log)
   * //
   * // Contents of ./path/to/my/file.json -
   * // {"meta":"abcd","keys":[...]}
   * //
   * // => { meta: 'abcd',
   * //      keys: [...] }
   *
   * @example <caption>Mixed input, multiple sources</caption>
   * let jwkSetPath = './path/to/my/file.json'
   * let jwkSet = { meta: 'abcd', keys: [...] }
   *
   * JWKSet.importKeys([jwkSet, jwkSetPath])
   *   .then(console.log)
   * //
   * // Contents of ./path/to/my/file.json -
   * // {"other":"efgh","keys":[...]}
   * //
   * // => { meta: 'abcd',
   * //      other: 'efgh',
   * //      keys: [...] }
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise.<JWKSet>} A promise that resolves a new JWKSet containing the generated key pairs.
   */
  static importKeys (data) {
    return Promise.resolve(new JWKSet())
      .then(jwks => jwks.importKeys(data).then(() => jwks))
  }

  /**
   * generateKeys
   *
   * @description
   * Generate additional keys and include them in the JWKSet.
   *
   * @example <caption>Simple RSA keypair</caption>
   * jwks.generateKeys('RS256')
   *   .then(console.log)
   * // => [
   * //      { kty: 'RSA' },
   * //      { kty: 'RSA' }
   * //    ]
   *
   * @example <caption>Multiple keypairs</caption>
   * jwks.generateKeys(['RS256', 'ES256'])
   *   .then(console.log)
   * // => [
   * //      [ { kty: 'RSA' },
   * //        { kty: 'RSA' } ],
   * //      [ { kty: 'EC' },
   * //        { kty: 'EC' } ] ]
   *
   * @example <caption>Object descriptor RSA keypair</caption>
   * let keyDescriptor = {
   *   alg: 'RS256',
   *   kid: 'custom',
   *   modulusLength: 1024
   * }
   *
   * jwks.generateKeys(keyDescriptor)
   *   .then(console.log)
   * // => [ { kty: 'RSA', kid: 'custom' },
   * //      { kty: 'RSA', kid: 'custom' } ]
   *
   * @example <caption>Mixed input, multiple keypairs</caption>
   * let keyDescriptor = {
   *   alg: 'RS512',
   *   modulusLength: 1024
   * }
   *
   * jwks.generateKeys([keyDescriptor, 'ES256'])
   *   .then(console.log)
   * // => [
   * //      [ { kty: 'RSA' },
   * //        { kty: 'RSA' } ],
   * //      [ { kty: 'EC' },
   * //        { kty: 'EC' } ]
   * //    ]
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise.<Array.<JWK>, Array.<Array.<JWK>>>} A promise that resolves the newly generated key pairs after they are added to the JWKSet instance.
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
      .then(keys => Promise.all(keys.map(key => JWK.fromCryptoKey(key, { alg }))))
      .then(keys => {
        this.keys = this.keys.concat(keys)
        return keys
      })
  }

  /**
   * importKeys
   *
   * @description
   * Import additional keys and include them in the JWKSet.
   *
   * @example <caption>Import keys from JSON string</caption>
   * let jsonJwkSet = '{"meta":"abcd","keys":[...]}'
   *
   * jwks.importKeys(jsonJwkSet)
   *   .then(console.log)
   * // => [ {...},
   * //      {...} ]
   *
   * @example <caption>Import keys from object</caption>
   * let jwkSet = {
   *   meta: 'abcd',
   *   keys: [...]
   * }
   *
   * jwks.importKeys(jwkSet)
   *   .then(console.log)
   * // => [ {...},
   * //      {...} ]
   *
   * @example <caption>Import keys from URL</caption>
   * let jwkSetUrl = 'https://idp.example.com/jwks'
   *
   * jwks.importKeys(jwkSetUrl)
   *   .then(console.log)
   * //
   * // HTTP/1.1 200 OK
   * // Content-Type: application/json
   * //
   * // {"meta":"abcd","keys":[...]}
   * //
   * // => [ {...},
   * //      {...} ]
   *
   * @example <caption>Import keys from file path</caption>
   * let jwkSetPath = './path/to/my/file.json'
   *
   * jwks.importKeys(jwkSetPath)
   *   .then(console.log)
   * //
   * // Contents of ./path/to/my/file.json -
   * // {"meta":"abcd","keys":[...]}
   * //
   * // => [ {...},
   * //      {...} ]
   *
   * @example <caption>Mixed input, multiple sources</caption>
   * let jwkSetPath = './path/to/my/file.json'
   * let jwkSet = { meta: 'abcd', keys: [...] }
   *
   * jwks.importKeys([jwkSet, jwkSetPath])
   *   .then(console.log)
   * //
   * // Contents of ./path/to/my/file.json -
   * // {"other":"efgh","keys":[...]}
   * //
   * // => [ {...},
   * //      {...},
   * //      {...},
   * //      {...} ]
   *
   * @param  {(String|Object|Array)} data
   * @param  {JWK} [kek] - Key encryption key.
   * @return {Promise.<Array.<JWK>>} A promise that resolves the newly imported key pairs after they are added to the JWKSet instance.
   *
   * @todo Import encrypted JWKSet
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
   * @description
   * Execute a filter query on the JWKSet keys.
   *
   * @example <caption>Function predicate</caption>
   * let predicate = key => key.key_ops.includes('sign')
   *
   * let filtered = jwks.filter(predicate)
   * // => [ { ..., key_ops: ['sign'] } ]
   *
   * @example <caption>MongoDB-like object predicate (see [Sift]{@link https://github.com/crcn/sift.js})</caption>
   * let predicate = { key_ops: { $in: ['sign', 'verify'] } }
   *
   * let filtered = jwks.filter(predicate)
   * // => [ { ..., key_ops: ['sign'] },
   * //      { ..., key_ops: ['verify'] } ]
   *
   * @param  {(Function|Object)} predicate - Filter function or predicate object
   * @return {Array.<JWK>} An array of JWKs matching the filter predicate.
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
   * @description
   * Execute a find query on the JWKSet keys.
   *
   * @example <caption>Function predicate</caption>
   * let predicate = key => key.key_ops.includes('sign')
   *
   * let filtered = jwks.find(predicate)
   * // => { ..., key_ops: ['sign'] }
   *
   * @example <caption>MongoDB-like object predicate (see [Sift]{@link https://github.com/crcn/sift.js})</caption>
   * let predicate = { key_ops: { $in: ['sign', 'verify'] } }
   *
   * let filtered = jwks.find()
   * // => { ..., key_ops: ['sign'] }
   *
   * @param  {(Function|Object)} predicate - Find function or predicate object
   * @return {JWK} The _first_ JWK matching the find predicate.
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
   * @ignore
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
   * @description
   * Serialize the JWKSet for storage or transmission.
   *
   * @param  {JWK} [kek] - optional encryption key
   * @return {String} The JSON serialized string of the JWKSet.
   *
   * @todo Encryption
   */
  exportKeys (kek) {
    return JSON.stringify(this)
  }

  /**
   * publicJwks
   *
   * @type {String}
   *
   * @description
   * The publishable JSON serialized string of the JWKSet. Returns _only public keys_.
   *
   * @todo Memoization
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
