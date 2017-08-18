'use strict'

/**
 * DataError
 */
class DataError extends Error {

  constructor (...args) {
    super(...args)
  }
}

/**
 * Export
 * @ignore
 */
module.exports = DataError
