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
  const message = 'Hello World!'
  const encodeImage = sig => sig.I.map(x => x.encode('hex')).join(',')
  let signatures = []
  describe('#sign', () => {
    it('should make signature', () => {
      for (const pi of Array(n).keys()) {
        signatures[pi] = mlsag.sign({ P, message, pi, x: keys[pi].map(k => k.getPrivate()) })
      }
    })
    it('should produce identical key images for the same key', () => {
      const anotherSignature = mlsag.sign({ P, message: 'Bye!', pi: 0, x: keys[0].map(k => k.getPrivate()) })
      assert.equal(encodeImage(signatures[0]), encodeImage(anotherSignature))
    })
    it('should produce different key images for different keys', () => {
      assert.notEqual(encodeImage(signatures[0]), encodeImage(signatures[1]))
    })
  })
  describe('#verify', () => {
    it('should verify correct signatures', () => {
      for (const pi of Array(n).keys()) {
        assert(mlsag.verify({ message, P, ...signatures[pi] }))
      }
    })
    it('should not verify bad signatures', () => {
      signatures[0].s[0][0] = signatures[0].s[0][0].add(new BN(1))
      assert(!mlsag.verify({ message, P, ...signatures[0] }))
    })
  })
})
