## [1.9.0](https://github.com/jasoet/gopki/compare/v1.8.0...v1.9.0) (2025-09-17)


### ✨ Features

* add testify assertion library for improved test quality ([b7fd524](https://github.com/jasoet/gopki/commit/b7fd5240ef95c9cfa570e5cc2ef5993653222d51))
* **keypair:** restructure RSA tests and enhance key handling ([bfab19f](https://github.com/jasoet/gopki/commit/bfab19f2c0fd2df4724096f8f18ac143331dfd9c))
* update README with encryption module and sync with CLAUDE.md changes ([2480aeb](https://github.com/jasoet/gopki/commit/2480aeb2d07835fdc7de4cd085353fdc3ae3565e))


### ✅ Tests

* add comprehensive unit tests for ECDSA and Ed25519 algorithms ([b2ea014](https://github.com/jasoet/gopki/commit/b2ea0149b64b15e3f3a1df153574ec055e3eb398))

## [1.8.0](https://github.com/jasoet/gopki/compare/v1.7.0...v1.8.0) (2025-09-17)


### ✨ Features

* **encryption:** add comprehensive CMS encryption and type-safe decryption tests ([ecdb06e](https://github.com/jasoet/gopki/commit/ecdb06e03f992b82086f0a981e5cfbc4200dd0be))


### ✅ Tests

* add unit tests for asymmetric encryption and decryption ([ba28806](https://github.com/jasoet/gopki/commit/ba28806d0748c8a1dd92b8e268adaa65db6ef5f4))

## [1.7.0](https://github.com/jasoet/gopki/compare/v1.6.0...v1.7.0) (2025-09-17)


### ✨ Features

* restructure encryption package with Go generics and sub-packages ([43a3064](https://github.com/jasoet/gopki/commit/43a306471226c9466ca55af91d60c358cd3241d0))


### ♻️ Refactoring

* **keypair:** move generic type aliases from pkcs12 package ([eacefdd](https://github.com/jasoet/gopki/commit/eacefdde4dd29e6dfa2e93c6b65e92706866a6fc))
* **pkcs12:** modernize with generics and type aliases ([1464af4](https://github.com/jasoet/gopki/commit/1464af4291994e93601fcebbcc60fffbdfe4e2e7))
* **pkcs12:** move certificate integration from cert package ([1957f4d](https://github.com/jasoet/gopki/commit/1957f4dd1a7849f49d5812bc5f1eeb73d0ffab8d))

## [1.6.0](https://github.com/jasoet/gopki/compare/v1.5.1...v1.6.0) (2025-09-16)


### ✨ Features

* generify P12 functions to return typed KeyPair instead of any ([9573e8d](https://github.com/jasoet/gopki/commit/9573e8dd5a2fa748ca4b26eb70611be6087dacfb))


### ♻️ Refactoring

* **pkcs12:** move P12 keypair functions to pkcs12 package ([d609b24](https://github.com/jasoet/gopki/commit/d609b24d7299cdf13f5a9fd19f210a66d927f873))

## [1.5.1](https://github.com/jasoet/gopki/compare/v1.5.0...v1.5.1) (2025-09-16)


### 🐛 Bug Fixes

* **encryption:** implement ephemeral key generation for public-key-only encryption ([6223510](https://github.com/jasoet/gopki/commit/62235104c5c8894856f3c61e6fda635d002e5831))
* remove Ed25519 public-key-only encryption due to complexity ([b35ad44](https://github.com/jasoet/gopki/commit/b35ad444e725a39eab212f09fbd3a4059899c9e7))

## [1.5.0](https://github.com/jasoet/gopki/compare/v1.4.1...v1.5.0) (2025-09-16)


### ✨ Features

* add encryption examples and fix ECDSA ephemeral key handling ([af0f367](https://github.com/jasoet/gopki/commit/af0f367c76766401e9af2975fb33acec754780a0))


### ♻️ Refactoring

* **encryption:** remove GPG support and simplify to CMS-only format ([1af7867](https://github.com/jasoet/gopki/commit/1af7867db7db1f20c566e05848586383efe9917f))

## [1.4.1](https://github.com/jasoet/gopki/compare/v1.4.0...v1.4.1) (2025-09-16)


### 🐛 Bug Fixes

* **formats:** correct package comment and add missing newline in raw.go ([56916ca](https://github.com/jasoet/gopki/commit/56916ca2f86606b2dab224e2fa4f3211097592cf))


### 📚 Documentation

* add comprehensive documentation for encryption, formats, and P12 packages ([b3fadf4](https://github.com/jasoet/gopki/commit/b3fadf41c272ebe65892d314ffdd5d62444b8c51)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)

## [1.4.0](https://github.com/jasoet/gopki/compare/v1.3.0...v1.4.0) (2025-09-16)


### ✨ Features

* **pkcs12:** implement comprehensive PKCS[#12](https://github.com/jasoet/gopki/issues/12) support across GoPKI packages ([b299c7a](https://github.com/jasoet/gopki/commit/b299c7a95ec25fffbeddd8a5e7e33594cf3b65bb))

## [1.3.0](https://github.com/jasoet/gopki/compare/v1.2.0...v1.3.0) (2025-09-16)


### ✨ Features

* **encryption:** add comprehensive high-level encryption API with tests ([f044a5e](https://github.com/jasoet/gopki/commit/f044a5e8f7aacf93349e0cfd74c94e944c50c704))


### 📚 Documentation

* **signing:** add comprehensive godoc documentation to signing package ([a1bde00](https://github.com/jasoet/gopki/commit/a1bde000546228419dcd91a40d326013cf4baa55)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)


### ♻️ Refactoring

* enhance testing workflow and remove unused code ([62c6a92](https://github.com/jasoet/gopki/commit/62c6a927634d3997f82cb889f9929dc4c933a6a5))
* **format:** enhance PEM package with comprehensive functionality and resolve circular imports ([aa6b7af](https://github.com/jasoet/gopki/commit/aa6b7af66934985006e07d778facf8fd4aa9c681))


### 🔧 Miscellaneous

* remove unused integration test file ([8e32cb6](https://github.com/jasoet/gopki/commit/8e32cb6c50aac2181e8bef6fd4e6fbd21214f0a3))

## [1.2.0](https://github.com/jasoet/gopki/compare/v1.1.1...v1.2.0) (2025-09-15)


### ✨ Features

* add comprehensive godoc documentation and DER format support ([45f41e8](https://github.com/jasoet/gopki/commit/45f41e8bdf1bc56b7634cd3bb000ea16171213fb))


### 📚 Documentation

* update documentation to reflect actual implementation status ([90b35d5](https://github.com/jasoet/gopki/commit/90b35d596990451d7e7197941aa3d7e4fedfef08)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)

## [1.1.1](https://github.com/jasoet/gopki/compare/v1.1.0...v1.1.1) (2025-09-15)


### 🐛 Bug Fixes

* **signing:** integrate formats package and add comprehensive test coverage ([1833d99](https://github.com/jasoet/gopki/commit/1833d994ad214728df1a573830784fc5857220e3)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)


### 📚 Documentation

* **readme:** enhance documentation with comprehensive signing features ([50205ca](https://github.com/jasoet/gopki/commit/50205caa1671e1d0b0335a685ad3b22eac9db7cd)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7) [PKCS#7](https://github.com/jasoet/PKCS/issues/7)

## [1.1.0](https://github.com/jasoet/gopki/compare/v1.0.0...v1.1.0) (2025-09-15)


### ✨ Features

* complete PKCS[#7](https://github.com/jasoet/gopki/issues/7)/CMS signature format implementation ([1b1629b](https://github.com/jasoet/gopki/commit/1b1629b05e158c7bf071de02ad12c38098590f2d))
* **signing:** implement document signing module ([7ec4c58](https://github.com/jasoet/gopki/commit/7ec4c584e63e81e6971c7337676794b0b9e28b40)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)


### 🐛 Bug Fixes

* remove redundant newline in example output ([76efb7c](https://github.com/jasoet/gopki/commit/76efb7c5d0c6713344739e81a69f5c09cdaa523b))


### 📚 Documentation

* integrate signing module documentation ([25fd22f](https://github.com/jasoet/gopki/commit/25fd22f77e7bb6c6a46f45785e7dbb43e1f6c9e4))
* refactor documentation to eliminate redundancy ([dfda7b6](https://github.com/jasoet/gopki/commit/dfda7b6aaef1070c6c832fc583bcc0221405d9a8))


### ♻️ Refactoring

* improve output directory structure and update legacy code ([79ed698](https://github.com/jasoet/gopki/commit/79ed6985a5bf23f816796257a2e40f9a92308002)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7) [PKCS#7](https://github.com/jasoet/PKCS/issues/7) [PKCS#7](https://github.com/jasoet/PKCS/issues/7)
* reorganize keypair example with proper directory structure ([4084f67](https://github.com/jasoet/gopki/commit/4084f672db248e98a748ede8e3ce14cdec5050ac))
* standardize certificates example output directory structure ([2cd95e8](https://github.com/jasoet/gopki/commit/2cd95e8553aabac17fa5aabe7471707a6c6e0025))


### 🔧 Miscellaneous

* add signatures/ directory to gitignore ([40be218](https://github.com/jasoet/gopki/commit/40be2188e57ddc77080fd58f9d456023c2e4bf2e))
* remove certificate files from git tracking ([e675d51](https://github.com/jasoet/gopki/commit/e675d51b0687af63da074c192259855541c3d76c))

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
