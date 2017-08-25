'use strict'

/**
 * Test dependencies
 * @ignore
 */
const cwd = process.cwd()
const path = require('path')
const fs = require('fs')
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
const { JWK } = require('../src')
const { DataError, OperationError } = require('../src/errors')

/**
 * Test Data
 * @ignore
 */
const { ECPrivateJWK, ECPublicJWK, A256GCMJWK, RSAPublicJWK } = require('./keys')

const ECPublicJWKString = fs.readFileSync(path.join(cwd, 'test', 'file_import', 'fileImportJWKTestData.json'), 'utf8')
const InvalidJWKString = fs.readFileSync(path.join(cwd, 'test', 'file_import', 'fileImportJWKTestData.json'), 'utf8')

const ECPublicJWKNoAlg = Object.assign({}, ECPublicJWK)
delete ECPublicJWKNoAlg.alg

const ECPublicJWKNoKid = Object.assign({}, ECPublicJWK)
delete ECPublicJWKNoKid.kid

const ECPublicJWKNoKty = Object.assign({}, ECPublicJWK)
delete ECPublicJWKNoKty.kty

const ECPublicJWKInvalidKty = Object.assign({}, ECPublicJWK)
ECPublicJWKInvalidKty.kty = 'invalid'

const plainTextData = 'data'
const plainTextAad = 'meta'
const encryptedData = {"iv":"RH9i_J861XN7qvgHYZ86ag","ciphertext":"qkrkiw","tag":"kqfdLgy8qopnzeKmC5JwQA"}
const encryptedDataWithAad = {"iv":"zrXJWOthT2tnFErPhWCrfw","ciphertext":"JWwKBg","tag":"txl7BQK4fxEP5cie2OQEZA","aad":"bWV0YQ"}
const signedData = 'MEQCIAIqNr8-7Pozi1D-cigvEKbkP5SpKezzEEDSqM9McIV1AiBd4gioW8njOpr29Ymrvjp46q7hA7lSOjAJpdi5TjHWsg'
const ecThumbprint = '45BLsBiWcghaEf_NF70Gf5oQcYLHaAtks0C48tT5SJ4'
const rsaThumbprint = 'fXSFPtseA8Q5nzSGuHhj5mHyNCGYUmznTbqEV-oo0Fc'
const symThumbprint = '25BH4hLm8A-gw20EHx8QvfDRCt3hKhFRYz9E_2Tge2c'

/**
 * Tests
 * @ignore
 */
describe('JWK', () => {

  describe('constructor', () => {

    it('should throw if no data is passed', () => {
      expect(() => new JWK()).to.throw('Invalid JWK')
    })

    it('should parse string input', () => {
      let jwk = new JWK(ECPublicJWKString)
      jwk.should.be.an.instanceOf(JWK)
    })

    it('should throw if it fails to parse string input', () => {
      expect(() => new JWK('invalid')).to.throw('Invalid JWK JSON String')
    })

    it('should throw if conflicting alg options are passed in', () => {
      expect(() => new JWK(ECPublicJWK, { alg: 'KS256' })).to.throw('Conflicting \'alg\' option')
    })

    it('should not throw if alg passed in twice but not conflicting', () => {
      expect(() => new JWK(ECPublicJWK, { alg: 'ES256' })).to.not.throw
    })

    it('should get alg from options if not on data', () => {
      let jwk = new JWK(ECPublicJWKNoAlg, { alg: 'ES256' })
      jwk.alg.should.equal('ES256')
    })

    it('should throw if alg is not present on data or options', () => {
      expect(() => new JWK(ECPublicJWKNoAlg, {})).to.throw('Valid \'alg\' required for JWK')
    })

    it('should throw if conflicting kid options are passed in', () => {
      expect(() => new JWK(ECPublicJWK, { kid: '1' })).to.throw('Conflicting \'kid\' option')
    })

    it('should not throw if kid passed in twice but not conflicting', () => {
      expect(() => new JWK(ECPublicJWK, { kid: '2' })).to.not.throw
    })

    it('should get kid from options if not on data', () => {
      let jwk = new JWK(ECPublicJWK, { alg: 'ES256', kid: '2' })
      jwk.kid.should.equal('2')
    })

    it('should assign key thumbprint as kid if not present on data or options', () => {
      let jwk = new JWK(ECPublicJWKNoKid)
      console.log(jwk)
      jwk.kid.should.equal(ecThumbprint)
    })

    it('should copy non-standard key metadata', () => {
      let json = Object.assign({}, ECPublicJWK, { meta: 'abc' })
      let jwk = new JWK(json)
      jwk.meta.should.equal('abc')
    })
  })

  describe('importKey', () => {

    it('should return a promise', () => {
      return JWK.importKey(ECPrivateJWK).should.be.fulfilled
    })

    it('should resolve an instance of JWK', () => {
      return JWK.importKey(ECPrivateJWK).should.eventually.be.an.instanceOf(JWK)
    })

    it('should have a cryptoKey property', () => {
      return JWK.importKey(ECPrivateJWK).then(jwk => {
        jwk.should.haveOwnProperty('cryptoKey')
      })
    })
  })

  describe('fromCryptoKey', () => {
    let cryptoKey

    before(() => {
      return JWK.importKey(ECPrivateJWK).then(jwk => {
        cryptoKey = jwk.cryptoKey
      })
    })

    it('should return a promise', () => {
      return JWK.fromCryptoKey(cryptoKey, { alg: 'EC256', kid: 'abcd123$' }).should.eventually.be.an.instanceOf(JWK)
    })

    it('should resolve an instance of JWK', () => {
      return JWK.fromCryptoKey(cryptoKey, { alg: 'EC256', kid: 'abcd123$' }).should.be.fulfilled
    })

    it('should have a cryptoKey property', () => {
      return JWK.fromCryptoKey(cryptoKey, { alg: 'EC256', kid: 'abcd123$' }).then(jwk => {
        jwk.should.haveOwnProperty('cryptoKey')
      })
    })
  })

  describe('sign', () => {
    let jwk

    before(() => {
      return JWK.importKey(ECPrivateJWK).then(key => jwk = key)
    })

    it('should return a promise', () => {
      return jwk.sign(plainTextData).should.be.fulfilled
    })

    it('should resolve a string', () => {
      return jwk.sign(plainTextData).should.eventually.be.a('string')
    })
  })

  describe('verify', () => {
    let jwk

    before(() => {
      return JWK.importKey(ECPublicJWK).then(key => jwk = key)
    })

    it('should return a promise', () => {
      return jwk.verify(plainTextData, signedData).should.be.fulfilled
    })

    it('should resolve a boolean', () => {
      return jwk.verify(plainTextData, signedData).should.eventually.be.true
    })

    it('should fail to verify the signature with incorrect data', () => {
      return jwk.verify(plainTextData + 'a', signedData).should.eventually.be.false
    })
  })

  describe('encrypt', () => {
    let jwk

    before(() => {
      return JWK.importKey(A256GCMJWK).then(key => jwk = key)
    })

    it('should return a promise', () => {
      return jwk.encrypt(plainTextData, Buffer.from('')).should.be.fulfilled
    })

    it('should resolve encrypted data', () => {
      return jwk.encrypt(plainTextData, Buffer.from('')).then(data => {
        data.should.haveOwnProperty('ciphertext')
        data.should.haveOwnProperty('iv')
        data.should.haveOwnProperty('tag')
        data.should.not.haveOwnProperty('aad')
      })
    })

    describe('with aad', () => {

      it('should resolve encrypted data', () => {
        return jwk.encrypt(plainTextData, plainTextAad).then(data => {
          data.should.haveOwnProperty('ciphertext')
          data.should.haveOwnProperty('iv')
          data.should.haveOwnProperty('tag')
          data.should.haveOwnProperty('aad')
        })
      })
    })
  })

  describe('decrypt', () => {
    let jwk

    before(() => {
      return JWK.importKey(A256GCMJWK).then(key => jwk = key)
    })

    it('should return a promise', () => {
      let { ciphertext, iv, tag } = encryptedData
      return jwk.decrypt(ciphertext, iv, tag).should.be.fulfilled
    })

    it('should resolve plain text data', () => {
      let { ciphertext, iv, tag } = encryptedData
      return jwk.decrypt(ciphertext, iv, tag).should.eventually.equal(plainTextData)
    })

    describe('with aad', () => {

      it('should reject if aad is omitted', () => {
        let { ciphertext, iv, tag } = encryptedDataWithAad
        return jwk.decrypt(ciphertext, iv, tag).should.be.rejected
      })

      it('should resolve plain text data', () => {
        let { ciphertext, iv, tag, aad } = encryptedDataWithAad
        return jwk.decrypt(ciphertext, iv, tag, aad).should.eventually.equal(plainTextData)
      })
    })
  })

  describe('thumbprint', () => {
    let ec, rsa, sym, kty, inv

    before(() => {
      return Promise.all([
        JWK.importKey(ECPublicJWK).then(key => ec = key),
        JWK.importKey(RSAPublicJWK).then(key => rsa = key),
        JWK.importKey(A256GCMJWK).then(key => sym = key),
        Promise.resolve(new JWK(ECPublicJWKNoKty)).then(key => kty = key),
        Promise.resolve(new JWK(ECPublicJWKInvalidKty)).then(key => inv = key)
      ])
    })

    it('should produce a thumbprint for RSA keys', () => {
      rsa.thumbprint().should.equal(rsaThumbprint)
    })

    it('should produce a thumbprint for EC keys', () => {
      ec.thumbprint().should.equal(ecThumbprint)
    })

    it('should produce a thumbprint for symmetric keys', () => {
      sym.thumbprint().should.equal(symThumbprint)
    })

    it('should throw if the JWK does not have a kty', () => {
      expect(() => kty.thumbprint()).to.throw('Invalid \'kty\'')
    })

    it('should throw if the kty is not valid', () => {
      expect(() => inv.thumbprint()).to.throw('Invalid \'kty\'')
    })
  })
})
