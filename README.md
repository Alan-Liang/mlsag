MLSAG in JavaScript
===================

A implementation of [MLSAG](https://eprint.iacr.org/2015/1098.pdf) in JavaScript.

**Disclaimer: DO NOT USE THIS PACKAGE IN ANY SERIOUS PROJECT.**

This package is in active development, and APIs are subject to change without following the semver rules. In fact, I do not even know if it is working properly and I am not so familiar with these things. PRs, issues and suggestions are extremely welcome.

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
const P = keys.map(kr => kr.map(k => k.getPublic()))
const pi = 2
const message = 'Hello World!'

const signature = mlsag.sign({ P, message, pi, x: keys[pi].map(k => k.getPrivate()) })
assert(mlsag.verify({ message, P, ...signature }))
```

See `test/mlsag.js` for a more detailed example.

## Docs

Only inline JSDoc is available for now.
