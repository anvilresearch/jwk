'use strict'

/**
 * Dependencies
 * @ignore
 */
const crypto = require('crypto')
const base64url = require('base64url')
const { JWA } = require('@trust/jwa')

/**
 * Module Dependencies
 * @ignore
 */
const { DataError } = require('./errors')

/**
 * JWK
 * @ignore
 */
class JWK {

  /**
   * constructor
   *
   * @class JWK
   *
   * @description
   * JSON Web Key ([IETF RFC7517](https://tools.ietf.org/html/rfc7517))
   *
   * @param  {Object} data
   * @param  {Object} [options={}] - Additional JWK metadata.
   */
  constructor (data, options = {}) {
    if (!data) {
      throw new DataError('Invalid JWK')
    }

    // Handle string input
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data)
      } catch (error) {
        throw new DataError('Invalid JWK JSON String')
      }
    }

    // Handle options input
    let metadata = Object.keys(options)
      .filter(key => {
        let dataValue = data[key]
        let optionsValue = options[key]

        if (dataValue && optionsValue && dataValue !== optionsValue) {
          throw new DataError(`Conflicting '${key}' option`)
        }

        return !dataValue && optionsValue
      })
      .reduce((state, key) => {
        state[key] = options[key]
        return state
      }, {})

    // Assign input
    Object.assign(this, data, metadata)

    // Enforce required properties
    if (!this.alg) {
      throw new DataError('Valid \'alg\' required for JWK')
    }

    if (!this.kid) {
      this.kid = this.thumbprint()
    }
  }

  /**
   * importKey
   *
   * @description
   * Import a JWK from JSON String or a JS Object.
   *
   * @param  {(String|Object)} data
   * @param  {Object} [options] - Additional JWK metadata.
   * @return {Promise.<JWK>} A promise that resolves the JWK instance.
   */
  static importKey (data, options) {
    return Promise.resolve()
      // Create instance
      .then(() => new JWK(data, options))

      // Import CryptoKey and assign to JWK
      .then(jwk => JWA.importKey(jwk).then(({ cryptoKey }) => {
        Object.defineProperty(jwk, 'cryptoKey', {
          value: cryptoKey,
          enumerable: false,
          configurable: false
        })

        return jwk
      }))
  }

  /**
   * fromCryptoKey
   *
   * @description
   * Import a JWK from a [WebCrypto CryptoKey](https://github.com/anvilresearch/webcrypto).
   *
   * @param  {CryptoKey} key - [WebCrypto CryptoKey]{@link https://github.com/anvilresearch/webcrypto}.
   * @param  {Object} [options] - Additional JWK metadata.
   * @return {Promise.<JWK>} A promise that resolves the JWK instance.
   */
  static fromCryptoKey (key, options) {
    // Export JWK
    return JWA.exportKey('jwk', key)

      // Create JWK instance and assign CryptoKey
      .then(data => {
        let jwk = new JWK(data, options)

        Object.defineProperty(jwk, 'cryptoKey', {
          value: key,
          enumerable: false,
          configurable: false
        })

        return jwk
      })
  }

  /**
   * sign
   *
   * @description
   * Sign arbitrary data using the JWK.
   *
   * @example <caption>Signing the string "test"</caption>
   * privateJwk.sign('test')
   *   .then(console.log)
   * //
   * // (line breaks for display only)
   * //
   * // => "MEUCIQCHwnGM8IsOJgfQsoPgs3hMd8
   * //     ahfWHM9ZNvj1K6i2yhKQIgWGOuXX43
   * //     lSTo-U8Pa8sURR53lv6Osjw-dtoLse
   * //     lftqQ"
   *
   * @param  {(String|Buffer)} data - The data to sign.
   * @return {Promise.<String>} A promise that resolves the base64url encoded signature string.
   */
  sign (data) {
    let { alg, cryptoKey } = this
    return JWA.sign(alg, cryptoKey, data)
  }

  /**
   * verify
   *
   * @description
   * Verify a signature using the JWK.
   *
   * @example <caption>Verify a signature of the string "test"</caption>
   * // base64url encoded signature string
   * let signature = `MEUCIQCHwnGM8IsOJgfQsoPgs3hMd8ahfWHM9ZN
   * vj1K6i2yhKQIgWGOuXX43lSTo-U8Pa8sURR53lv6Osjw-dtoLselftqQ`
   *
   * publicJwk.verify('test', signature)
   *   .then(console.log)
   * // => true
   *
   * @param  {(String|Buffer)} data - The data to verify.
   * @param  {String} signature - A base64url signature string.
   * @return {Promise.<Boolean>} A promise that resolves the boolean result of the signature verification.
   */
  verify (data, signature) {
    let { alg, cryptoKey } = this
    return JWA.verify(alg, cryptoKey, signature, data)
  }

  /**
   * encrypt
   *
   * @description
   * Encrypt arbitrary data using the JWK.
   *
   * @example <caption>Encrypt the string "data"</caption>
   * secretJwk.encrypt('data')
   *   .then(console.log)
   * // => { iv: 'u0l3ttqUFDQ8mcRboHv5Vw',
   * //      ciphertext: 'yq3K4w',
   * //      tag: 'fHlZ__uuUnHn0ac-Lnrr-A' }
   *
   * @param  {(String|Object)} data - The data to encrypt.
   * @param  {(String|Buffer)} [aad] - Additional non-encrypted integrity protected data (AES-GCM).
   * @return {Promise.<Object>} A promise that resolves an object containing the base64url encoded `iv`, `ciphertext` and `tag` (AES-GCM).
   */
  encrypt (data, aad) {
    let { alg, cryptoKey } = this
    return JWA.encrypt(alg, cryptoKey, data, aad)
  }

  /**
   * decrypt
   *
   * @description
   * Decrypt data using the JWK.
   *
   * @example <caption>Decrypt encrypted string "test"</caption>
   * // base64url encoded data
   * let ciphertext = 'yq3K4w'
   * let iv = 'u0l3ttqUFDQ8mcRboHv5Vw'
   * let tag = 'fHlZ__uuUnHn0ac-Lnrr-A'
   *
   * secretJwk.decrypt(ciphertext, iv, tag)
   *   .then(console.log)
   * // => "data"
   *
   * @param  {(String|Buffer)} ciphertext - The encrypted data to decrypt.
   * @param  {(String|Buffer)} iv - The initialization vector.
   * @param  {(String|Buffer)} [tag] - The authorization tag (AES-GCM).
   * @param  {(String|Buffer)} [aad] - Additional non-encrypted integrity protected data (AES-GCM).
   * @return {Promise.<String>} A promise that resolves the plaintext data.
   */
  decrypt (ciphertext, iv, tag, aad) {
    let { alg, cryptoKey } = this
    return JWA.decrypt(alg, cryptoKey, ciphertext, iv, tag, aad)
  }

  /**
   * thumbprint
   *
   * @description
   * Calculate the SHA-256 JWK Thumbprint according to [RFC7638]{@link https://tools.ietf.org/html/rfc7638}.
   * This method is used to create a unique `kid` if none is specified.
   *
   * @example <caption>SHA-256 Thumbprint</caption>
   * jwk.thumbprint()
   * //
   * // (line breaks for display only)
   * //
   * // => "45BLsBiWcghaEf_NF70Gf5oQcYLHaA
   * //     tks0C48tT5SJ4"
   *
   * @return {String} JWK Thumbprint String
   */
  thumbprint () {
    let { kty } = this
    let data

    // RSA JWK Thumbprint Fields
    if (kty === 'RSA') {
      let { e, n } = this
      data = { e, kty, n }

    // ECDSA JWK Thumbprint Fields
    } else if (kty === 'EC') {
      let { crv, x, y } = this
      data = { crv, kty, x, y }

    // Symmetric JWK Thumbprint Fields
    } else if (kty === 'oct') {
      let { k } = this
      data = { k, kty }

    // Invalid kty
    } else {
      throw new DataError('Invalid \'kty\'')
    }

    let hash = crypto.createHash('sha256')
    let json = JSON.stringify(data)

    hash.update(json)
    return base64url(hash.digest())
  }

  /**
   * generateProtected
   *
   * @description
   * Use key metadata to generate a JWS protected header object.
   *
   * @example <caption>Basic JWS Header with JWC</caption>
   * jwk.generateProtected({ jwc: 'base64url encoded compact jwc' })
   * // => { alg: 'RS256',
   * //      kid: 'abcd123$',
   * //      jwc: 'base64url encoded compact jwc' }
   *
   * @example <caption>Basic JWS Header with JKU</caption>
   * jwk.generateProtected({ jku: 'https://example.com/jwks' })
   * // => { alg: 'RS256',
   * //      kid: 'abcd123$',
   * //      jku: 'https://example.com/jwks' }
   *
   * @param  {Object} props - Additional properties to include in header.
   * @return {Object} JWS Header
   */
  generateProtected (props) {
    let { alg, kid, key_ops, use } = this
    let header = Object.assign({}, { alg, kid }, props)

    // Check key_ops or use
    if (!(Array.isArray(key_ops) && key_ops.includes('sign')) && !(use && use === 'sig')) {
      throw new DataError('Invalid key usage option')
    }

    // Check for mandatory properties
    if (!header.alg) {
      throw new DataError('\'alg\' is required')
    }

    if (!header.kid) {
      throw new DataError('\'kid\' is required')
    }

    if (!header.jku && !header.jwc) {
      throw new DataError('Either \'jku\' or \'jwc\' is required')
    }

    return header
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = JWK
