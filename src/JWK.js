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

    if (data.alg && options.alg && data.alg !== options.alg) {
      throw new DataError('Conflicting algorithm option')

    } else if (!data.alg && options.alg) {
      data.alg = options.alg

    } else if (!data.alg && !options.alg) {
      throw new DataError('Valid JWA algorithm required for JWK')
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
      .then(() => new JWK(data))
      .then(jwk => {
        return JWA.importKey(jwk)
          .then(cryptoKey => {
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
