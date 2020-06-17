/**
 * @see https://eprint.iacr.org/2015/1098.pdf
 */

const EC = require('elliptic').ec
const BN = require('bn.js')

const emptyArray = length => Array(length).fill(null)
const zip = (a, b) => {
  if (a.length !== b.length) throw new TypeError('Invalid array length passed to zip()')
  const c = []
  for (let i = 0; i < a.length; i++) {
    c.push(a[i])
    c.push(b[i])
  }
  return c
}

class MLSAG {
  /**
   * Create a MLSAG instance.
   * @param {object} options
   * @param {string} options.curve curve to use
   * @param {function} options.hash hash constructor such as `require('sha3').SHA3`, should at least have #update and #digest methods
   * @param {any[]} options.hashOptions options to pass to the hash constructor
   */
  constructor ({ curve = 'ed25519', hash, hashOptions }) {
    this._ec = new EC(curve)
    this._hashConstructor = hash
    this._hashConstructorOptions = hashOptions
  }

  // helper functions
  _hash (...messages) {
    const hashObject = new this._hashConstructor(...this._hashConstructorOptions)
    for (const i of messages) hashObject.update(i.encode ? i.encode('hex') : i.toString(16))
    return new BN(hashObject.digest('hex'), 16)
  }
  _hashPoint (...messages) { return this._mul(this._hash(...messages), this._ec.g) }
  _randomKeyPairs (length) { return emptyArray(length).map(() => this._ec.genKeyPair()) }
  _randomKeyPairMatrix (x, y) { return emptyArray(x).map(() => this._randomKeyPairs(y)) }
  _randomVector (length) { return this._randomKeyPairs(length).map(key => key.getPrivate()) }
  _randomMatrix (x, y) { return this._randomKeyPairMatrix(x, y).map(kr => kr.map(k => k.getPrivate())) }
  _mul (a, b) { return b.mul(a) }
  _add (a, b) { return a.add(b) }
  _sub (a, b) { return a.sub(b) }
  _hashMessage (message, Lk, Rk) { return this._hash(message, ...zip(Lk, Rk)) }
  _clr ({ m, n, message, k, c, L, R, s, P, I }, ignoreC = false) {
    const kPlusOne = (k + 1) % n
    if (!ignoreC) c[kPlusOne] = this._hashMessage(message, L[k], R[k])
    L[kPlusOne] = emptyArray(m).map((_, j) => this._add(this._mul(s[kPlusOne][j], this._ec.g), this._mul(c[kPlusOne], P[kPlusOne][j])))
    R[kPlusOne] = emptyArray(m).map((_, j) => this._add(this._mul(s[kPlusOne][j], this._hashPoint(P[kPlusOne][j])), this._mul(c[kPlusOne], I[j])))
  }

  /**
   * @typedef {object} SignResult
   * @property {Point[]} I key image
   * @property {BN} c0 c_0
   * @property {BN[][]} s s
   */

  /**
   * Signs a message.
   * @param {object} options
   * @param {string|BN} options.message message to sign
   * @param {Point[][]} options.P decoys
   * @param {number} options.pi index of the private key in decoys
   * @param {BN[]} options.x private key
   * @returns {SignResult}
   */
  sign ({ P, message, pi, x }) {
    const n = P.length, m = P[pi].length
    if (!P.every(x => x.length === m)) throw new TypeError('Invalid public keyring')
    if (!P[pi].every((pk, j) => this._mul(x[j], this._ec.g).eq(pk))) throw new Error('Invalid private key')
    const I = P[pi].map((_, j) => this._mul(x[j], this._hashPoint(P[pi][j])))
    const s = this._randomMatrix(n, m)
    const alpha = this._randomVector(m)
    const L = emptyArray(n)
    const R = emptyArray(n)
    L[pi] = alpha.map(aj => this._mul(aj, this._ec.g))
    R[pi] = alpha.map((aj, j) => this._mul(aj, this._hashPoint(P[pi][j])))
    const c = emptyArray(n)
    for (const k of emptyArray(n - 1).map((_, i) => (i + pi) % n)) this._clr({ m, n, message, k, c, L, R, s, P, I })
    const piMinusOne = (pi + n - 1) % n
    c[pi] = this._hashMessage(message, L[piMinusOne], R[piMinusOne])
    s[pi] = alpha.map((aj, j) => this._sub(aj, this._mul(x[j], c[pi])).umod(this._ec.n))
    return { I, c0: c[0], s }
  }

  /**
   * Verifies a signature.
   * @param {object} options
   * @param {string|BN} options.message message to sign
   * @param {Point[][]} options.P decoys
   * @param {Point[]} options.I key image
   * @param {BN} options.c0 c_0
   * @param {BN[][]} options.s s
   */
  verify ({ message, P, I, c0, s }) {
    const n = P.length, m = P[0].length
    if (!P.every(x => x.length === m)) throw new TypeError('Invalid public keyring')
    const c = emptyArray(n)
    c[0] = c0
    const L = emptyArray(n), R = emptyArray(n)
    this._clr({ m, n, message, k: -1, c, L, R, s, P, I }, true)
    for (const k of Array(n).keys()) this._clr({ m, n, message, k, c, L, R, s, P, I })
    return c[0].eq(c0)
  }
}

exports.MLSAG = MLSAG
