MLSAG in JavaScript
===================

[paper]: https://eprint.iacr.org/2015/1098.pdf

An implementation of [MLSAG][paper] in JavaScript.

**Disclaimer: DO NOT USE THIS PACKAGE IN ANY SERIOUS PROJECT.**

This package is still in development, and APIs are subject to change without following the semver rules. In fact, I do not even know if it is working properly and I am not so familiar with these things. PRs, issues and suggestions are extremely welcome.

Please take a look at the [paper] before using this package as the APIs uses symbols in the paper.

## Example

```javascript
import { MLSAG } from 'mlsag'
import { SHA3 } from 'sha3'
import assert from 'assert'

const mlsag = new MLSAG({
  hash: SHA3,
  hashOptions: [ 512 ],
})

// FIXME: use a public API
const keys = mlsag._randomKeyPairMatrix(5, 2)
const pi = 2
const P = keys.map(kr => kr.map(k => k.getPublic()))
const x = keys[pi].map(k => k.getPrivate())
const message = 'Hello World!'

// raw signature
const signature = mlsag.sign({ P, message, pi, x })
assert(mlsag.verify({ message, P, ...signature }))

// encoded signature
const encodedSignature = mlsag.sign({ P, message, pi, x, encode: true })
assert(mlsag.verify({ message, P, signature: encodedSignature }))
```

See `test/mlsag.js` for a more detailed example.

## Docs

Only inline JSDoc is available for now.
