'use strict'

/**
 * Test dependencies
 * @ignore
 */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
const sinon = require('sinon')
const sinonChai = require('sinon-chai')

/**
 * Assertions
 * @ignore
 */
chai.use(chaiAsPromised)
chai.should()
chai.use(sinonChai)
const expect = chai.expect

/**
 * Code Under Test
 * @ignore
 */
const { JWA } = require('@trust/jwa')
const { JWKSet, JWK } = require('../src')

/**
 * Test Data
 * @ignore
 */
const { ECPrivateJWK, ECPublicJWK } = require('./keys')
const ECDSAKeyGenDescriptor = {
  alg: 'ES256',
  key_ops: ['sign', 'verify']
}

/**
 * Tests
 * @ignore
 */
describe('JWKSet', () => {

  describe('constructor', () => {
    let meta = 'abc'

    describe('with object input', () => {

      it('should assign metadata', () => {
        let jwkset = new JWKSet({ meta })
        jwkset.meta.should.equal(meta)
      })

      it('should create keys array if not present', () => {
        let jwkset = new JWKSet({})
        jwkset.keys.should.be.instanceOf(Array)
      })

      it('should not override the keys array if provided', () => {
        let jwkset = new JWKSet({ keys: [meta] })
        jwkset.keys[0].should.equal(meta)
      })
    })

    describe('with array input', () => {

      it('should treat the array as `keys`', () => {
        let keys = [meta]
        let jwkset = new JWKSet(keys)
        jwkset.keys.should.equal(keys)
        jwkset.keys[0].should.equal(meta)
      })
    })

    describe('with no input', () => {

      it('should create keys array if not present', () => {
        let jwkset = new JWKSet({})
        jwkset.keys.should.be.instanceOf(Array)
      })
    })
  })

  describe('generateKeys', () => {

    describe('static', () => {

      beforeEach(() => {
        sinon.stub(JWKSet.prototype, 'generateKeys').resolves()
      })

      afterEach(() => {
        JWKSet.prototype.generateKeys.restore()
      })

      it('should return a promise', () => {
        return JWKSet.generateKeys().should.be.fulfilled
      })

      it('should resolve a JWKSet', () => {
        return JWKSet.generateKeys().should.eventually.be.a.instanceOf(JWKSet)
      })

      it('should defer to member generateKeys', () => {
        return JWKSet.generateKeys(ECDSAKeyGenDescriptor).then(jwks => {
          jwks.generateKeys.should.be.calledWith(ECDSAKeyGenDescriptor)
        })
      })

      it('should reject if generateKeys rejects', () => {
        JWKSet.prototype.generateKeys.restore()
        sinon.stub(JWKSet.prototype, 'generateKeys').rejects()
        return JWKSet.generateKeys().should.be.rejected
      })
    })

    describe('member', () => {
      let jwks

      beforeEach(() => {
        jwks = new JWKSet()
      })

      it('should return a promise', () => {
        return jwks.generateKeys('ES256').should.be.fulfilled
      })

      it('should reject on invalid input', () => {
        return jwks.generateKeys(null).should.be.rejected
      })

      describe('with JWA alg string input', () => {

        it('should resolve the new keypair', () => {
          return jwks.generateKeys('ES256').then(keys => keys.length.should.equal(2))
        })

        it('should reject with invalid alg', () => {
          return jwks.generateKeys('ES255').should.be.rejected
        })
      })

      describe('with array input', () => {

        it('should resolve an array of new keypairs', () => {
          return jwks.generateKeys(['ES256', 'ES256']).then(keys => {
            keys.length.should.equal(2)
            expect(Array.isArray(keys[0])).to.be.true
          })
        })

        it('should reject if one entry fails', () => {
          return jwks.generateKeys(['ES256', 'ES255']).should.be.rejected
        })
      })

      describe('with key descriptor object input', () => {

        it('should resolve the new keypair', () => {
          return jwks.generateKeys(ECDSAKeyGenDescriptor).should.be.fulfilled
        })

        it('should reject if `alg` is not present', () => {
          return jwks.generateKeys({ key_ops: ['sign', 'verify'] }).should.be.rejected
        })

        it('should use default value if `key_ops` is not present', () => {
          return jwks.generateKeys({ alg: 'ES256' }).should.be.fulfilled
        })
      })
    })
  })

  describe('importKeys', () => {

    describe('static', () => {

      beforeEach(() => {
        sinon.stub(JWKSet.prototype, 'importKeys').resolves()
      })

      afterEach(() => {
        JWKSet.prototype.importKeys.restore()
      })

      it('should return a promise', () => {
        return JWKSet.importKeys().should.be.fulfilled
      })

      it('should resolve a JWKSet', () => {
        return JWKSet.importKeys().should.eventually.be.a.instanceOf(JWKSet)
      })

      it('should defer to member importKeys', () => {
        return JWKSet.importKeys(ECDSAKeyGenDescriptor).then(jwks => {
          jwks.importKeys.should.be.calledWith(ECDSAKeyGenDescriptor)
        })
      })

      it('should reject if importKeys rejects', () => {
        JWKSet.prototype.importKeys.restore()
        sinon.stub(JWKSet.prototype, 'importKeys').rejects()
        return JWKSet.importKeys().should.be.rejected
      })
    })

    describe('member', () => {
      let jwks

      beforeEach(() => {
        jwks = new JWKSet()
      })

      it('should return a promise', () => {
        return jwks.importKeys(ECPrivateJWK).should.be.fulfilled
      })

      it('should reject on invalid input', () => {
        return jwks.importKeys(null).should.be.rejected
      })
    })
  })

  describe('filter', () => {

  })

  describe('find', () => {

  })

  describe('exportKeys', () => {

  })
})
