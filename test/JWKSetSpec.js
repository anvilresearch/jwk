'use strict'

/**
 * Test dependencies
 * @ignore
 */
const cwd = process.cwd()
const path = require('path')
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
const { DataError, OperationError } = require('../src/errors')

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
      let meta = 'abc'

      beforeEach(() => {
        jwks = new JWKSet()
      })

      it('should return a promise', () => {
        return jwks.importKeys(ECPrivateJWK).should.be.fulfilled
      })

      it('should reject on invalid input', () => {
        return jwks.importKeys(null).should.be.rejected
      })

      describe('with array input', () => {

        it('should resolve an array of imported JWKs', () => {
          return jwks.importKeys([ECPrivateJWK]).then(keys => {
            keys.length.should.equal(1)
            keys[0].should.be.an.instanceOf(JWK)
          })
        })

        it('should resolve empty array with empty input', () => {
          return jwks.importKeys([]).then(keys => {
            keys.length.should.equal(0)
          })
        })

        it('should reject with invalid input', () => {
          return jwks.importKeys([null]).should.be.rejected
        })

        it('should reject if at least one array item is invalid input', () => {
          return jwks.importKeys([ECPrivateJWK, null]).should.be.rejected
        })
      })

      describe('with stringified JSON input', () => {

        it('should resolve the imported JWK', () => {
          return jwks.importKeys(JSON.stringify(ECPrivateJWK)).then(key => {
            key.should.be.a.instanceOf(JWK)
          })
        })

        it('should reject with invalid JSON input', () => {
          return jwks.importKeys('{invalid').should.be.rejected
        })

        it('should reject with invalid JWK', () => {
          return jwks.importKeys('{}').should.be.rejected
        })

        it('should accept a JSON array', () => {
          return jwks.importKeys(JSON.stringify([ECPrivateJWK, ECPublicJWK])).then(keys => {
            keys.length.should.equal(2)
            keys[0].should.be.an.instanceOf(JWK)
          })
        })
      })

      describe('with jwks url input', () => {

        it('should resolve the array of imported JWKs', () => {
          return jwks.importKeys('https://www.googleapis.com/oauth2/v3/certs').then(keys => {
            expect(Array.isArray(keys)).to.be.true
            keys[0].should.be.an.instanceOf(JWK)
          })
        })

        it('should reject with invalid url', () => {
          return jwks.importKeys('http://localhost:4200/a/b/c').should.be.rejected
        })
      })

      describe('with file path input', () => {

        it('with JWK content should resolve the imported JWK', () => {
          return jwks.importKeys(path.join(cwd, 'test', 'file_import', 'fileImportJWKTestData.json')).then(jwk => {
            jwk.should.be.an.instanceOf(JWK)
          })
        })

        it('with JWKSet content should resolve the array of imported JWKs', () => {
          return jwks.importKeys(path.join(cwd, 'test', 'file_import', 'fileImportJWKSetTestData.json')).then(keys => {
            keys.length.should.equal(1)
            keys[0].should.be.an.instanceOf(JWK)
          })
        })

        it('should reject with invalid file contents', () => {
          return jwks.importKeys(path.join(cwd, 'test', 'file_import', 'fileImportInvalidTestData.json')).should.be.rejected
        })

        it('should reject with invalid file path', () => {
          return jwks.importKeys('invalid').should.be.rejected
        })
      })

      describe('with JWKSet object input', () => {

        it('should resolve the array of imported JWKs', () => {
          return jwks.importKeys({ keys: [ECPrivateJWK, ECPublicJWK] }).then(keys => {
            keys.length.should.equal(2)
            keys[0].should.be.an.instanceOf(JWK)
          })
        })

        it('should retain non-standard metadata on the JWKSet', () => {
          return jwks.importKeys({ meta, keys: [ECPrivateJWK, ECPublicJWK] }).then(() => {
            jwks.meta.should.equal(meta)
          })
        })
      })
    })
  })

  describe('filter', () => {
    let jwks

    before(() => {
      return JWKSet.importKeys([ECPrivateJWK, ECPublicJWK]).then(keys => jwks = keys)
    })

    it('should return a promise', () => {
      return jwks.filter(() => false).should.be.fulfilled
    })

    it('should resolve an array', () => {
      return jwks.filter(() => false).then(keys => expect(Array.isArray(keys)).to.be.true)
    })

    describe('with function predicate', () => {

      it('should resolve an array of JWKs', () => {
        return jwks.filter(key => key.key_ops.includes('sign')).then(keys => {
          keys.length.should.equal(1)
          keys[0].should.be.an.instanceOf(JWK)
        })
      })

      it('should reject if the function throws', () => {
        return jwks.filter(key => key.a.b.c).should.be.rejected
      })
    })

    describe('with object predicate', () => {

      it('should resolve an array of JWKs', () => {
        return Promise.all([
          jwks.filter({ key_ops: 'sign' }).then(keys => {
            keys.length.should.equal(1)
            keys[0].should.be.an.instanceOf(JWK)
          }),
          jwks.filter({ kty: 'EC' }).then(keys => {
            keys.length.should.equal(2)
            keys[0].should.be.an.instanceOf(JWK)
          })
        ])
      })
    })

    describe('with invalid predicate', () => {

      it('should reject', () => {
        return jwks.filter('invalid').should.be.rejected
      })
    })
  })

  describe('find', () => {
    let jwks

    before(() => {
      return JWKSet.importKeys([ECPrivateJWK, ECPublicJWK]).then(keys => jwks = keys)
    })

    it('should return a promise', () => {
      return jwks.find(() => false).should.be.fulfilled
    })

    it('should resolve the first result', () => {
      return jwks.find(() => true).then(jwk => expect(jwk).to.be.an.instanceOf(JWK))
    })

    it('should resolve undefined if no result is found', () => {
      return jwks.find(() => false).then(keys => expect(keys).to.be.undefined)
    })

    describe('with function predicate', () => {

      it('should return a JWK', () => {
        return jwks.find(key => key.key_ops.includes('sign')).then(jwk => jwk.should.be.an.instanceOf(JWK))
      })

      it('should reject if the function throws', () => {
        return jwks.find(key => key.a.b.c).should.be.rejected
      })
    })

    describe('with object predicate', () => {

      it('should resolve a JWK', () => {
        return Promise.all([
          jwks.find({ key_ops: 'sign' }).then(jwk => jwk.should.be.an.instanceOf(JWK)),
          jwks.find({ kty: 'EC' }).then(jwk => jwk.should.be.an.instanceOf(JWK))
        ])
      })
    })

    describe('with invalid predicate', () => {

      it('should reject', () => {
        return jwks.find('invalid').should.be.rejected
      })
    })
  })

  describe('rotate', () => {
    let jwks = new JWKSet()

    // Placeholder test
    it('should resolve the JWKSet', () => {
      return jwks.rotate().should.eventually.be.an.instanceOf(JWKSet)
    })
  })

  describe('exportKeys', () => {
    let jwks = new JWKSet()

    it('should return a string', () => {
      return jwks.exportKeys().should.be.a('string')
    })
  })
})
