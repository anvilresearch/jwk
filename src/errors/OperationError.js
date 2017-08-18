'use strict'

/**
 * OperationError
 */
class OperationError extends Error {

  constructor (...args) {
    super(...args)
  }
}

/**
 * Export
 * @ignore
 */
module.exports = OperationError
