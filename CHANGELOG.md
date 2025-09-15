## 1.0.0 (2025-09-15)


### ✨ Features

* add Taskfile for streamlined development workflow and update docs with PEM type alias ([697968b](https://github.com/jasoet/gopki/commit/697968b6b1f2858f4e5ffc5d320b465cafb2a6bd))
* **cert:** add comprehensive X.509 certificate functionality ([4f97760](https://github.com/jasoet/gopki/commit/4f97760fa4889cdb8f060dd314d6f5c2a742c721))
* **docs:** add comprehensive documentation and PEM type alias ([ced39f1](https://github.com/jasoet/gopki/commit/ced39f17da3441623c9a297e8228c58ffc09ca4f))
* **format:** add DER format support with PEM interchange ([2a25b3f](https://github.com/jasoet/gopki/commit/2a25b3fe9362980bb83b1e53c82d623ca501d206))
* **format:** add SSH format support with PEM/DER interchange ([ac892d3](https://github.com/jasoet/gopki/commit/ac892d3198673d204bca4eda63d228de030bcb8d))
* initial GoPKI implementation with type-safe generic parsing ([c0c016e](https://github.com/jasoet/gopki/commit/c0c016e3b1692fac8d34fde2365d97a1fed25bc6))
* **keypair:** enhance keypair package with advanced PEM and key utilities ([f2038fc](https://github.com/jasoet/gopki/commit/f2038fc09eedad8e16180ba7f5e5d8bcee61aaff))
* **keypair:** implement generic type-safe key generation wrapper ([533ee77](https://github.com/jasoet/gopki/commit/533ee77f6d3e69ddc78e16ca63fed8e7596d6639))
* **ssh:** implement proper SSH private key parsing and conversion ([ac73b41](https://github.com/jasoet/gopki/commit/ac73b41acf3c64cdbf75445efd9ef82e18e81ba2))


### ♻️ Refactoring

* **cert:** move certificate functionality to dedicated package and add intermediate CA support ([f66bf35](https://github.com/jasoet/gopki/commit/f66bf3542437128682a27c5dfd7b88e9eea7dc54))
* **examples,tests:** update to use new generic GenerateKeyPair API ([a19ef7b](https://github.com/jasoet/gopki/commit/a19ef7b04c923e38ef949591796d00ebbac90a3b))
* **examples:** reorganize examples and fix build conflicts ([85938d1](https://github.com/jasoet/gopki/commit/85938d167b57262bfa07e78844b3e6766f58e700))
* **examples:** restructure examples and add GetPublicKey tests ([d518bdd](https://github.com/jasoet/gopki/commit/d518bdd7f3581f01d0196d439431dacc619bb90b))
* **keypair:** remove keypair package and related tests ([0c55824](https://github.com/jasoet/gopki/commit/0c5582416c2f1cc48ac2bef5baba4ce25b8edffa))
* **keypair:** remove redundant tests and simplify API integration ([57641da](https://github.com/jasoet/gopki/commit/57641da29807fff8c3bc24d5b766a7e00492c171))
* move key generation logic to dedicated `algo` package ([70bfb65](https://github.com/jasoet/gopki/commit/70bfb65adad1ce1f1f0946be61e631d4b39f9fa9))
* remove utils package and migrate file I/O to standard library ([15fda96](https://github.com/jasoet/gopki/commit/15fda9628829442c4696a23ff30fd6c1a2fdbd42))
* **test:** restructure tests to follow Go conventions ([133065d](https://github.com/jasoet/gopki/commit/133065d51b0a723444ea7a2544f6ee693e28786b))


### 👷 CI/CD

* add semantic release workflow and configuration ([e9fd2d5](https://github.com/jasoet/gopki/commit/e9fd2d51a2e9771fc1722f0f23b0ccec208ace62))


### 🔧 Miscellaneous

* **examples:** remove outdated `gopki-examples` file ([5bd0dc0](https://github.com/jasoet/gopki/commit/5bd0dc089f165c76ea1881dd2f008d7a65b761f6))
