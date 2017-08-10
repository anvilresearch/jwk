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
 * JWKSet
 * @ignore
 */
class JWKSet {

  /**
   * constructor
   *
   * @class
   * JWKSet
   */
  constructor (data) {
    // TODO
    Object.assign(this, data)
  }

  /**
   * generateKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   */
  static generateKeys (data) {
    return Promise.resolve(new JWKSet())
      .then(jwks => jwks.generateKeys(data))
  }

  /**
   * importKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   */
  static importKeys (data) {
    return Promise.resolve(new JWKSet())
      .then(jwks => jwks.importKeys(data))
  }

  /**
   * generateKeys
   *
   * @param  {(String|Object|Array)} data
   * @return {Promise}
   */
  generateKeys (data) {
    return Promise.resolve(this)
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
