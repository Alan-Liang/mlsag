const assert = require('assert')
const { MLSAG } = require('..')
const { SHA3 } = require('sha3')
const BN = require('bn.js')

describe('MLSAG', () => {
  const mlsag = new MLSAG({
    hash: SHA3,
    hashOptions: [ 512 ],
  })
  const n = 5, m = 2
  const keys = mlsag._randomKeyPairMatrix(n, m)
  const P = keys.map(kr => kr.map(k => k.getPublic()))
  const xs = keys.map(kr => kr.map(k => k.getPrivate()))
  const message = 'Hello World!'
  const encodeImage = sig => sig.I.map(x => x.encode('hex')).join(',')
  let signatures = [], encodedSignatures = []
  describe('#sign', () => {
    it('should make non-encoded signature', () => {
      for (const pi of Array(n).keys()) {
        signatures[pi] = mlsag.sign({ P, message, pi, x: xs[pi] })
      }
    })
    it('should make encoded signature', () => {
      for (const pi of Array(n).keys()) {
        encodedSignatures[pi] = mlsag.sign({ P, message, pi, x: xs[pi], encode: true })
      }
    })
    it ('should encode and decode signatures correctly', () => {
      for (const pi of Array(n).keys()) {
        assert.equal(
          encodedSignatures[pi],
          mlsag.encodeSignature(mlsag.decodeSignature(encodedSignatures[pi]))
        )
      }
    })
    it('should produce identical key images for the same key', () => {
      const anotherSignature = mlsag.sign({ P, message: 'Bye!', pi: 0, x: xs[0] })
      assert.equal(encodeImage(signatures[0]), encodeImage(anotherSignature))
    })
    it('should produce different key images for different keys', () => {
      assert.notEqual(encodeImage(signatures[0]), encodeImage(signatures[1]))
    })
  })
  describe('#verify', () => {
    it('should verify correct non-encoded signatures', () => {
      for (const pi of Array(n).keys()) {
        assert(mlsag.verify({ message, P, ...signatures[pi] }))
      }
    })
    it('should verify correct encoded signatures', () => {
      for (const pi of Array(n).keys()) {
        assert(mlsag.verify({ message, P, signature: encodedSignatures[pi] }))
      }
    })
    it('should not verify bad signatures', () => {
      signatures[0].s[0][0] = signatures[0].s[0][0].add(new BN(1))
      assert(!mlsag.verify({ message, P, ...signatures[0] }))
    })
    it('should not verify signatures signed by unknown signer', () => {
      const invalidKeys = mlsag._randomKeyPairs(m)
      const signature = mlsag.sign({ P: [ invalidKeys.map(x => x.getPublic()), ...P.slice(1) ], message, pi: 0, x: invalidKeys.map(k => k.getPrivate()) })
      assert(!mlsag.verify({ message, P, ...signature }))
    })
  })
})
