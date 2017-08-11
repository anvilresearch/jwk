'use strict'

/**
 * Test dependencies
 * @ignore
 */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')

/**
 * Assertions
 * @ignore
 */
chai.use(chaiAsPromised)
chai.should()
const expect = chai.expect

/**
 * Code Under Test
 * @ignore
 */
const { JWKSet, JWK } = require('../src')

/**
 * Test Data
 * @ignore
 */

/**
 * Tests
 * @ignore
 */
describe('JWKSet', () => {

  describe('generateKeys', () => {

    describe('static', () => {
      it('should return a promise', () => {
        return JWKSet.generateKeys('RS256').should.be.fulfilled
      })

      it('should resolve a JWKSet', () => {
        return JWKSet.generateKeys('RS256').should.eventually.be.a.instanceOf(JWKSet)
      })

      it('should generate and import', () => {
        return JWKSet.generateKeys('RS256').then(jwks => {
          jwks.keys.length.should.equal(2)
          jwks.keys[0].should.be.instanceOf(JWK)
        })
      })

      it('should generate multiple keys', () => {
        return JWKSet.generateKeys(['RS256', 'RS256']).then(jwks => {
          jwks.keys.length.should.equal(4)
          jwks.keys[3].should.be.instanceOf(JWK)
        })
      })

      it('should allow mixed input', () => {
        return JWKSet.generateKeys(['RS256', { alg: 'RS256', modulusLength: 4096, kid: 'abc', key_ops: ['sign', 'verify'] }]).then(jwks => {
          jwks.keys.length.should.equal(4)
          jwks.keys[3].should.be.instanceOf(JWK)
        })
      })

      it('should require key_ops in object descriptors', () => {
        return JWKSet.generateKeys({ alg: 'RS256' }).should.be.rejected
      })
    })

    describe('member', () => {
      let jwks

      beforeEach(() => {
        jwks = new JWKSet()
      })

      it('should return a promise', () => {
        return jwks.generateKeys('RS256').should.be.fulfilled
      })

      it('should return newly generatedKeys', () => {
        return jwks.generateKeys(['RS256', 'RS256'])
          .then(generated => {
            generated.length.should.equal(2)
            jwks.keys.length.should.equal(4)
          })
      })
    })
  })
})
