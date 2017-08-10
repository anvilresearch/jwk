'use strict'

/**
 * Dependencies
 * @ignore
 */

/**
 * Module Dependencies
 * @ignore
 */

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
  constructor (data) {
    // TODO
    Object.assign(this, data)
  }

  /**
   * importKey
   *
   * @param  {(String|Object)} data
   * @return {Promise}
   */
  static importKey (data) {
    return Promise.resolve(new JWK())
  }

  /**
   * sign
   *
   * @param  {(JWT|JWD)} data
   * @return {Promise}
   */
  sign (data) {
    return Promise.resolve()
  }

  /**
   * verify
   *
   * @param  {Object} header - Protected header
   * @param  {Object} payload
   * @param  {String} signature
   * @return {Promise}
   */
  verify (header, payload, signature) {
    return Promise.resolve()
  }

  /**
   * encrypt
   *
   * @param  {(String|Object)} data
   * @param  {JWK} key - Encryption key
   * @return {Promise}
   */
  encrypt (data, key) {
    return Promise.resolve()
  }

  /**
   * decrypt
   *
   * @param  {(String|Object)} data
   * @param  {JWK} key - Decryption key
   * @return {Promise}
   */
  decrypt (data, key) {
    return Promise.resolve()
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = JWK
