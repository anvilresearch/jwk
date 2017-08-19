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
const { DataError } = require('./errors')

/**
 * JWK
 * @ignore
 */
class JWK {

  /**
   * constructor
   *
   * @class
   * JSON Web Key
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

    // Handle object input
    if (data.alg && options.alg && data.alg !== options.alg) {
      throw new DataError('Conflicting algorithm option')

    } else if (!data.alg && options.alg) {
      data.alg = options.alg

    } else if (!data.alg && !options.alg) {
      throw new DataError('Valid JWA algorithm required for JWK')
    }

    // Handle kid transferral
    if (data.kid && options.kid && data.kid !== options.kid) {
      throw new DataError('Conflicting key identifier option')

    } else if (!data.kid && options.kid) {
      data.kid = options.kid

    } else if (!data.kid && !options.kid) {
      throw new DataError('Valid JWA key identifier required for JWK')
    }

    Object.assign(this, data)
  }

  /**
   * importKey
   *
   * @param  {(String|Object)} data
   * @return {Promise}
   */
  static importKey (data, options = {}) {
    return Promise.resolve()
      .then(() => new JWK(data, options))
      .then(jwk => {
        return JWA.importKey(jwk)
          .then(({ cryptoKey }) => {
            Object.defineProperty(jwk, 'cryptoKey', {
              value: cryptoKey,
              enumerable: false,
              configurable: false
            })

            return jwk
          })
      })
  }

  /**
   * fromCryptoKey
   *
   * @param  {CryptoKey} key
   * @param  {Object} [options]
   * @return {Promise}
   */
  static fromCryptoKey (key, options) {
    return JWA.exportKey('jwk', key)
      .then(data => {
        let jwk = new JWK(data, options)
        Object.defineProperty(jwk, 'cryptoKey', { value: key, enumerable: false, configurable: false })
        return jwk
      })
  }

  /**
   * sign
   *
   * @param  {(String|Buffer)} data
   * @return {Promise}
   */
  sign (data) {
    let { alg, cryptoKey } = this
    return JWA.sign(alg, cryptoKey, data)
  }

  /**
   * verify
   *
   * @param  {(String|Buffer)} data
   * @param  {String} signature
   * @return {Promise}
   */
  verify (data, signature) {
    let { alg, cryptoKey } = this
    return JWA.verify(alg, cryptoKey, signature, data)
  }

  /**
   * encrypt
   *
   * @param  {(String|Object)} data
   * @param  {(String|Buffer)} aad - integrity protected data
   * @return {Promise}
   */
  encrypt (data, aad) {
    let { alg, cryptoKey } = this
    return JWA.encrypt(alg, cryptoKey, data, aad)
  }

  /**
   * decrypt
   *
   * @param  {(String|Object)} data
   * @param  {(String|Buffer)} iv
   * @param  {(String|Buffer)} tag
   * @param  {(String|Buffer)} aad
   * @return {Promise}
   */
  decrypt (data, iv, tag, aad) {
    let { alg, cryptoKey } = this
    return JWA.decrypt(alg, cryptoKey, data, iv, tag, aad)
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = JWK
