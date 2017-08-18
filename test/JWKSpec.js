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
const { ECPrivateJWK, ECPublicJWK } = require('./keys')
const ECPublicJWKString = fs.readFileSync(path.join(cwd, 'test', 'file_import', 'fileImportJWKTestData.json'), 'utf8')
const InvalidJWKString = fs.readFileSync(path.join(cwd, 'test', 'file_import', 'fileImportJWKTestData.json'), 'utf8')
const ECPublicJWKNoAlg = Object.assign({}, ECPublicJWK)
delete ECPublicJWKNoAlg.alg

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
      expect(() => new JWK(ECPublicJWK, { alg: 'KS256' })).to.throw('Conflicting algorithm option')
    })

    it('should not throw if alg passed in twice but not conflicting', () => {
      expect(() => new JWK(ECPublicJWK, { alg: 'ES256' })).to.not.throw
    })

    it('should get alg from options if not on data', () => {
      let jwk = new JWK(ECPublicJWKNoAlg, { alg: 'ES256' })
      jwk.alg.should.equal('ES256')
    })

    it('should throw if alg is not present on data or options', () => {
      expect(() => new JWK(ECPublicJWKNoAlg, { alg: 'ES256' })).to.throw
    })

    it('should copy non-standard key metadata', () => {
      let json = Object.assign({}, ECPublicJWK, { meta: 'abc' })
      let jwk = new JWK(json)
      jwk.meta.should.equal('abc')
    })
  })

  describe('importKey', () => {

  })

  describe('fromCryptoKey', () => {

  })

  describe('sign', () => {

  })

  describe('verify', () => {

  })

  describe('encrypt', () => {

  })

  describe('decrypt', () => {

  })
})
