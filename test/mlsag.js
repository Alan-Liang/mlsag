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
  const everyPi = f => () => Array.from(Array(n).keys()).forEach(f)
  const signatures = [], encodedSignatures = []
  describe('#sign', () => {
    it('should make non-encoded signature', everyPi(pi => signatures[pi] = mlsag.sign({ P, message, pi, x: xs[pi] })))
    it('should make encoded signature', everyPi(pi => encodedSignatures[pi] = mlsag.sign({ P, message, pi, x: xs[pi], encode: true })))
    it('should produce identical key images for the same key', () => {
      const anotherSignature = mlsag.sign({ P, message: 'Bye!', pi: 0, x: xs[0] })
      assert.equal(encodeImage(signatures[0]), encodeImage(anotherSignature))
    })
    it('should produce different key images for different keys', () => assert.notEqual(encodeImage(signatures[0]), encodeImage(signatures[1])))
    it('should throw TypeError on non-rectangular decoys', () => assert.throws(
      () => mlsag.sign({ P: [ ...P, [] ], message, pi: 0, x: xs[0] }),
      { name: 'TypeError', message: 'Invalid decoys' },
    ))
    it('should throw Error on invalid private key', () => assert.throws(
      () => mlsag.sign({ P, message, pi: 0, x: [ xs[1][0], ...xs[0].slice(1) ] }),
      { name: 'Error', message: 'Invalid private key' },
    ))
  })
  describe('#encode #decode', () => {
    it('should encode and decode signatures properly', everyPi(pi => {
      assert.equal(mlsag.encodeSignature(signatures[pi]),
                   mlsag.encodeSignature(signatures[pi]))
      assert.equal(mlsag.encodeSignature(signatures[pi]),
                   mlsag.encodeSignature(mlsag.decodeSignature(mlsag.encodeSignature(signatures[pi]))))
      assert.equal(encodedSignatures[pi],
                   mlsag.encodeSignature(mlsag.decodeSignature(encodedSignatures[pi])))
    }))
    it('should throw TypeError on non-string signature', () => assert.throws(
      () => mlsag.decodeSignature({}),
      { name: 'TypeError', message: 'Signature must be a string' },
    ))
  })
  describe('#verify', () => {
    it('should verify correct non-encoded signatures', everyPi(pi => assert(mlsag.verify({ message, P, ...signatures[pi] }))))
    it('should verify correct encoded signatures', everyPi(pi => assert(mlsag.verify({ message, P, signature: encodedSignatures[pi] }))))
    it('should verify correct non-encoded signatures with #encode()', everyPi(pi => assert(mlsag.verify({ message, P, signature: mlsag.encodeSignature(signatures[pi]) }))))
    it('should verify correct encoded signatures with #decode()', everyPi(pi => assert(mlsag.verify({ message, P, ...mlsag.decodeSignature(encodedSignatures[pi]) }))))
    it('should not verify bad signatures', () => {
      signatures[0].s[0][0] = signatures[0].s[0][0].add(new BN(1))
      assert(!mlsag.verify({ message, P, ...signatures[0] }))
    })
    it('should not verify signatures signed by unknown signer', () => {
      const invalidKeys = mlsag._randomKeyPairs(m)
      const signature = mlsag.sign({ P: [ invalidKeys.map(x => x.getPublic()), ...P.slice(1) ], message, pi: 0, x: invalidKeys.map(k => k.getPrivate()) })
      assert(!mlsag.verify({ message, P, ...signature }))
    })
    it('should not verify signature signed with wrong message', () => assert(!mlsag.verify({ message: 'Bye world!', P, signature: encodedSignatures[0] })))
    it('should throw TypeError on non-rectangular decoys', () => assert.throws(
      () => mlsag.verify({ P: [ ...P, [] ], message, signature: encodedSignatures[0] }),
      { name: 'TypeError', message: 'Invalid decoys' },
    ))
    it('should throw TypeError on no input', () => assert.throws(
      () => mlsag.verify({}),
      { name: 'TypeError', message: 'No signature input' },
    ))
    it('should throw TypeError on duplicate input', () => assert.throws(
      () => mlsag.verify({ message, P, ...signatures[0], signature: mlsag.encodeSignature(signatures[0]) }),
      { name: 'TypeError', message: 'Duplicate signature input' },
    ))
  })
})
