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
const { RSAPrivateJWK, RSAPublicJWK } = require('./keys')
const RSAKeyGenDescriptor = {
  alg: 'RS256',
  modulusLength: 1024, // low for testing
  kid: 'abc',
  key_ops: ['sign', 'verify']
}

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
        return JWKSet.generateKeys([RSAKeyGenDescriptor, RSAKeyGenDescriptor]).then(jwks => {
          jwks.keys.length.should.equal(4)
          jwks.keys[3].should.be.instanceOf(JWK)
        })
      })

      it('should allow mixed input', () => {
        return JWKSet.generateKeys([RSAKeyGenDescriptor, 'RS256']).then(jwks => {
          jwks.keys.length.should.equal(4)
          jwks.keys[3].should.be.instanceOf(JWK)
        })
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

      it('should return newly generated keys', () => {
        return jwks.generateKeys(['RS256', 'RS256'])
          .then(generated => {
            generated.length.should.equal(2)
            jwks.keys.length.should.equal(4)
          })
      })
    })
  })

  describe('importKeys', () => {

    describe('static', () => {

      it('should return a promise', () => {
        return JWKSet.importKeys(RSAPublicJWK).should.be.fulfilled
      })

      it('should resolve a JWKSet', () => {
        return JWKSet.importKeys(RSAPublicJWK).should.eventually.be.a.instanceOf(JWKSet)
      })

      it('should import keys', () => {
        return JWKSet.importKeys(RSAPublicJWK).then(jwks => {
          jwks.keys[0].should.be.instanceOf(JWK)
        })
      })

      it('should import multiple keys', () => {
        return JWKSet.importKeys([RSAPublicJWK, RSAPublicJWK]).then(jwks => {
          jwks.keys[1].should.be.instanceOf(JWK)
        })
      })
    })

    describe('member', () => {
      let jwks

      beforeEach(() => {
        jwks = new JWKSet()
      })

      it('should return a promise', () => {
        return jwks.importKeys(RSAPublicJWK).should.be.fulfilled
      })

      it('should return newly imported keys', () => {
        return jwks.importKeys([RSAPublicJWK, RSAPrivateJWK])
          .then(imported => {
            imported.length.should.equal(2)
            jwks.keys.length.should.equal(2)
          })
      })
    })
  })
})
