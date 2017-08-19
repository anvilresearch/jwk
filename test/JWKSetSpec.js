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
const nock = require('nock')

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
        let jwks_endpoint

        before(() => {
          jwks_endpoint = nock('http://idp.example.com')
            .get('/jwks')
            .reply(200, { keys: [ECPublicJWK] })
        })

        it('should resolve the array of imported JWKs', () => {
          return jwks.importKeys('http://idp.example.com/jwks').then(keys => {
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

    it('should return an array', () => {
      expect(Array.isArray(jwks.filter(() => false))).to.be.true
    })

    describe('with function predicate', () => {

      it('should return an array of JWKs', () => {
        let keys = jwks.filter(key => key.key_ops.includes('sign'))
        keys.length.should.equal(1)
        keys[0].should.be.an.instanceOf(JWK)
      })

      it('should throw if predicate function is malformed', () => {
        expect(() => jwks.filter(key => key.a.b.c)).to.throw
      })
    })

    describe('with object predicate', () => {

      it('should return an array of JWKs', () => {
        let privateKeys = jwks.filter({ key_ops: 'sign' })
        privateKeys.length.should.equal(1)
        privateKeys[0].should.be.an.instanceOf(JWK)

        let ellipticKeys = jwks.filter({ kty: 'EC' })
        ellipticKeys.length.should.equal(2)
        ellipticKeys[0].should.be.an.instanceOf(JWK)
      })

      it('should throw if predicate object is malformed', () => {
        expect(() => jwks.filter('invalid')).to.throw('Invalid predicate')
      })
    })
  })

  describe('find', () => {
    let jwks

    before(() => {
      return JWKSet.importKeys([ECPrivateJWK, ECPublicJWK]).then(keys => jwks = keys)
    })

    describe('with function predicate', () => {

      it('should return a JWK', () => {
        let jwk = jwks.find(key => true)
        jwk.should.be.an.instanceOf(JWK)
      })

      it('should throw if predicate function is malformed', () => {
        expect(() => jwks.find(key => key.a.b.c)).to.throw
      })
    })

    describe('with object predicate', () => {

      it('should return a JWK', () => {
        let jwk = jwks.find({ key_ops: 'sign' })
        jwk.should.be.an.instanceOf(JWK)
      })

      it('should throw if predicate object is malformed', () => {
        expect(() => jwks.find('invalid')).to.throw('Invalid predicate')
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

  describe('publicJwks', () => {
    let jwks

    before(() => {
      return JWKSet.importKeys([ECPrivateJWK, ECPublicJWK]).then(keys => jwks = keys)
    })

    it('should return a valid JSON string', () => {
      expect(() => JSON.parse(jwks.publicJwks)).to.not.throw
    })

    it('should include JWKSet metadata', () => {
      jwks.meta = 'abc'
      let json = JSON.parse(jwks.publicJwks)
      json.meta.should.equal('abc')
    })
  })
})
