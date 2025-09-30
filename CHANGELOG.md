## [1.17.2](https://github.com/jasoet/gopki/compare/v1.17.1...v1.17.2) (2025-09-30)


### 🐛 Bug Fixes

* **test:** reduce parallelism in compatibility tests to prevent runner OOM ([aafacf5](https://github.com/jasoet/gopki/commit/aafacf565f90044c362088e6941effec73e981e2))

## [1.17.1](https://github.com/jasoet/gopki/compare/v1.17.0...v1.17.1) (2025-09-30)


### 🐛 Bug Fixes

* **test:** add 10-minute timeout to compatibility tests ([c4a27ce](https://github.com/jasoet/gopki/commit/c4a27ce9e4037c42fb4c384deb3c9a856db0a8ed))


### 👷 CI/CD

* add parallel compatibility tests and examples jobs ([57a2be9](https://github.com/jasoet/gopki/commit/57a2be973ccabae3c4e1ffe318464f145bae6b87))
* improve workflow setup and run examples instead of building ([1a943ce](https://github.com/jasoet/gopki/commit/1a943ce19a1bbc6b5ca70d3e5c11952d0b62c2b5))

## [1.17.0](https://github.com/jasoet/gopki/compare/v1.16.0...v1.17.0) (2025-09-30)


### ✨ Features

* **ci:** optimize test pipeline with Taskfile integration ([2253f55](https://github.com/jasoet/gopki/commit/2253f559fe9336e97fb1bbb98392fedd01b0ce1e))

## [1.16.0](https://github.com/jasoet/gopki/compare/v1.15.0...v1.16.0) (2025-09-30)


### ✨ Features

* **encryption:** add OpenSSL-compatible envelope encryption mode ([6c487ab](https://github.com/jasoet/gopki/commit/6c487abf8550615ff25056ff7bd57e2d22041206)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7) [PKCS#7](https://github.com/jasoet/PKCS/issues/7)


### 📚 Documentation

* clean up documentation by removing excessive line numbers and counts ([e6f237e](https://github.com/jasoet/gopki/commit/e6f237e7e5d15a9c18e95e90e766f4e7ba6c6eca))
* **compatibility:** add detailed compatibility report and testing instructions ([8d3c2ee](https://github.com/jasoet/gopki/commit/8d3c2eed6a032c4c0433ce13673059577d549f4a))
* update compatibility report with OpenSSL envelope encryption ([1c66fe8](https://github.com/jasoet/gopki/commit/1c66fe8f715014f1cc2394f2bd7649b1aeade88d)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)


### ✅ Tests

* **compatibility:** add comprehensive OpenSSL envelope encryption test ([e88e2ac](https://github.com/jasoet/gopki/commit/e88e2ac241e444c4009d7a629325fac92f2ea5b8)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)
* **compatibility:** add encryption compatibility tests with OpenSSL for multiple algorithms ([248ea29](https://github.com/jasoet/gopki/commit/248ea297f525565157ccc4f3319f92eba3140573))
* **compatibility:** handle OpenSSL version differences for Ed25519 ([c85f8bb](https://github.com/jasoet/gopki/commit/c85f8bbe1da3340216bc6837e8a83b742749f29a))
* **compatibility:** update encryption tests to handle expected RSA-OAEP and AES-GCM limitations ([023e611](https://github.com/jasoet/gopki/commit/023e61159cbc74792df1a8c4101162d231c4e48f))
* **encryption/compatibility:** add comprehensive tests for CMS cycle and encryption compatibility ([686c922](https://github.com/jasoet/gopki/commit/686c922de728df9333d8ef84012edc1b0fcdb3ea))


### 👷 CI/CD

* install OpenSSL and OpenSSH for compatibility tests ([918ec3c](https://github.com/jasoet/gopki/commit/918ec3cb05c58dd1dc33ef8d71d1789417782c97))
* simplify workflow by removing compatibility tests from CI ([861aeba](https://github.com/jasoet/gopki/commit/861aebae536d70505cdeeefc403f5bedce440493))
* streamline workflow to use Taskfile and exclude compatibility tests ([575aaa7](https://github.com/jasoet/gopki/commit/575aaa7f9b8a42b5311a8832494ec15c48d77cac))
* update upload-artifact action from v3 to v4 ([09980e1](https://github.com/jasoet/gopki/commit/09980e1c79b914210f24b19c1e3b20d68d9f5166))
* upgrade OpenSSL to 3.3.2 for full Ed25519 support ([ccf55cb](https://github.com/jasoet/gopki/commit/ccf55cbe01c8da6b9fe454953fcb5ebc8a198658))
* **workflows:** add test suite and coverage upload to semantic-release workflow ([bb75dda](https://github.com/jasoet/gopki/commit/bb75dda116c0746e3c7cb83abcb6596b7823d9de))

## [1.15.0](https://github.com/jasoet/gopki/compare/v1.14.0...v1.15.0) (2025-09-22)


### ✨ Features

* **cert:** support custom key usage and extended key usage in certificate creation ([bf5a37c](https://github.com/jasoet/gopki/commit/bf5a37c59e3dd5ed1dbb945e15d94079002bc993))
* **crypto:** add debug utilities for Ed25519 PKCS[#7](https://github.com/jasoet/gopki/issues/7) signature handling ([cce095b](https://github.com/jasoet/gopki/commit/cce095ba76af12ad68535ee12439d6c9889da394))
* **crypto:** add Ed25519 PKCS[#7](https://github.com/jasoet/gopki/issues/7) signature creation and verification functions ([c1aaf55](https://github.com/jasoet/gopki/commit/c1aaf554e8a129121d9048ff656dfe79e2b3a5d5))
* **crypto:** add Ed25519 to X25519 conversion and modular arithmetic utilities ([59cfbfc](https://github.com/jasoet/gopki/commit/59cfbfc96fd4b83dca6ee7893a4faa96fe7a17c9))
* **signing:** replace VerifyDetachedSignature with VerifySignature for PKCS[#7](https://github.com/jasoet/gopki/issues/7) verification ([3b301b1](https://github.com/jasoet/gopki/commit/3b301b14131287355f6f7590ebb138cfc17c1b0b))


### 🐛 Bug Fixes

* **encryption:** update error messaging to reference RFC 7748 and improve Ed25519 compatibility ([2256547](https://github.com/jasoet/gopki/commit/2256547ec7ebca6a7c17402cf81a625a06ced3bd))


### ✅ Tests

* **compatibility:** add advanced SSH compatibility and edge case tests ([25ce698](https://github.com/jasoet/gopki/commit/25ce698063ca895347d910dd9eb2e17617429a3e))


### 🔧 Miscellaneous

* **crypto:** remove example Ed25519 RFC 8419 validation code and update tests ([fdc29ea](https://github.com/jasoet/gopki/commit/fdc29ea0fa3c05a84081c6df70641ac9910d6275)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7)

## [1.14.0](https://github.com/jasoet/gopki/compare/v1.13.0...v1.14.0) (2025-09-19)


### ✨ Features

* **compatibility:** add comprehensive OpenSSL signing compatibility tests ([8384feb](https://github.com/jasoet/gopki/commit/8384febeac073ca076cd00a0e87261bca01bc731)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7) [PKCS#7](https://github.com/jasoet/PKCS/issues/7)

## [1.13.0](https://github.com/jasoet/gopki/compare/v1.12.0...v1.13.0) (2025-09-19)


### ✨ Features

* **compatibility:** add comprehensive SSH compatibility testing framework ([c80494e](https://github.com/jasoet/gopki/commit/c80494edacada7040c44b57397c90945e3b27a0e))


### 📚 Documentation

* **compatibility:** add OpenSSL compatibility framework documentation ([2834925](https://github.com/jasoet/gopki/commit/2834925c1ee6864a82681b8412ca4ccde44ac02b))


### ✅ Tests

* **compatibility:** add build tag and update OpenSSL compatibility test command ([e35f1a8](https://github.com/jasoet/gopki/commit/e35f1a8f5221d7e4085ab7b4d8af669e1d18855b))
* **compatibility:** add OpenSSL certificate compatibility testing framework ([8fbb926](https://github.com/jasoet/gopki/commit/8fbb9269abe122e48aff264599da88e99c7644a1))
* **compatibility:** clean up cert_test.go by removing duplicate struct fields and unused imports ([b0e1e12](https://github.com/jasoet/gopki/commit/b0e1e126af1f48ec89773508e7b1582550d786d5))

## [1.12.0](https://github.com/jasoet/gopki/compare/v1.11.0...v1.12.0) (2025-09-18)


### ✨ Features

* **asymmetric:** add Ed25519 <-> X25519 key conversion utilities with comprehensive tests ([d76912c](https://github.com/jasoet/gopki/commit/d76912c08c7d82d5d97e66ea30226f75390368c7))
* **asymmetric:** implement ECDSA and Ed25519 encryption/decryption with ephemeral keys ([e7e89ce](https://github.com/jasoet/gopki/commit/e7e89ceee3f4e8ac0b2a988dea1ce372afd2004c))
* **encryption:** enable ECDSA public key and certificate-based encryption, improve Ed25519 error messages ([4b838e7](https://github.com/jasoet/gopki/commit/4b838e7330b4bea2d67b0681472ff107f53f4eab))


### 🐛 Bug Fixes

* **signing:** enhance PKCS[#7](https://github.com/jasoet/gopki/issues/7) verification for content and certificate validation ([f1f7252](https://github.com/jasoet/gopki/commit/f1f7252206a6e2646f5bd4ba0557f32d57007b45))


### 📚 Documentation

* **certificates:** restructure certificate module documentation ([63ddf08](https://github.com/jasoet/gopki/commit/63ddf08dd9c736801eaa409398103d6e77b0343b)), closes [PKCS#12](https://github.com/jasoet/PKCS/issues/12)
* **examples:** add comprehensive PKCS[#12](https://github.com/jasoet/gopki/issues/12) documentation and examples ([168e014](https://github.com/jasoet/gopki/commit/168e0144f0d1e9dc543ce737603fdbb40c3c1527))
* **examples:** enhance encryption examples, add implementation notes and detailed summaries ([000080e](https://github.com/jasoet/gopki/commit/000080eb86a25c9e199fadf9541ac271a68dbddd))
* **examples:** expand Signing module documentation ([0cf1034](https://github.com/jasoet/gopki/commit/0cf103488159224ea826fdd5f0180dc1b54c4c70))
* **examples:** revamp encryption examples with multi-algorithm support and CMS compliance ([a3bed05](https://github.com/jasoet/gopki/commit/a3bed0556a283ede7a7d0e8dec97530452b8d1e3))
* **examples:** update signing module examples and documentation ([431b3ff](https://github.com/jasoet/gopki/commit/431b3ffe450dca976d6fb35b2b8d29fbd5fd0d22)), closes [PKCS#7](https://github.com/jasoet/PKCS/issues/7) [PKCS#7](https://github.com/jasoet/PKCS/issues/7)
* restructure documentation and rebuild comprehensive project docs ([c636eab](https://github.com/jasoet/gopki/commit/c636eab1d86dec70f4f33a503ed5d357b3a84dd6))


### ♻️ Refactoring

* **examples:** enhance keypair module examples with comprehensive, structured use cases ([44e6af4](https://github.com/jasoet/gopki/commit/44e6af47e2d0e4f0a42a4351788a29f9bf08b56f))


### ✅ Tests

* **asymmetric:** add tests for ephemeral key utilities, key agreement, and AES key derivation ([d292e00](https://github.com/jasoet/gopki/commit/d292e001a91f1187e98b5a18835ca102a75d0bd9))
* **cert/keypair:** refactor key pair generation and format handling for consistency ([8f14c47](https://github.com/jasoet/gopki/commit/8f14c47d9af68a29b2109bc908b58f81fe12f068))
* **cert/signing:** remove redundant test cases for certificate and signing modules ([3fbff22](https://github.com/jasoet/gopki/commit/3fbff229548d28d5628785281979f453284f35cf))
* **cert:** refactor test keypair generation for consistency ([f9c8580](https://github.com/jasoet/gopki/commit/f9c85803de6429ced33d9301722a4db453198352))
* **encryption:** add edge case tests for invalid encrypt and decrypt options ([9078c5e](https://github.com/jasoet/gopki/commit/9078c5ee1521ed41872231eae3b3fbf2ce154bb9))
* **encryption:** add unit tests for certificate, envelope, and encryption functionality ([2f65412](https://github.com/jasoet/gopki/commit/2f65412a071000cbef9570ea33beedda62e84bcd))
* **encryption:** replace hardcoded key sizes with algo.KeySize constants ([96372b3](https://github.com/jasoet/gopki/commit/96372b35abf7d028ad1358795ec6e8b50af49e6e))
* **keypair:** adopt Manager for key generation in tests and remove unused envelope test file ([45c6148](https://github.com/jasoet/gopki/commit/45c61482b05f4493c80160fb043495f3aec49407))
* **pkcs12:** add comprehensive integration tests for PKCS[#12](https://github.com/jasoet/gopki/issues/12) functionality ([6f4ef8c](https://github.com/jasoet/gopki/commit/6f4ef8cb67294d4f1d8ba6352371065cbc9ce86c))
* **pkcs12:** add extensive unit tests for key pair and certificate functionalities ([19dd5f5](https://github.com/jasoet/gopki/commit/19dd5f55843ec06decd5df8ffafaae4eb5ea4ecf)), closes [PKCS#12](https://github.com/jasoet/PKCS/issues/12)
* **pkcs12:** refactor integration tests to use Manager for key generation ([3c467ef](https://github.com/jasoet/gopki/commit/3c467eff98d3cb7888f37fc9a4e376c7b72de3a7))


### 🔧 Miscellaneous

* add and configure golangci-lint for comprehensive code quality and security checks ([be68b7e](https://github.com/jasoet/gopki/commit/be68b7e99740faca1f56c73d35bc75353602f990))
* **asymmetric:** remove Ed25519 <-> X25519 key conversion utilities and related tests ([9ff8096](https://github.com/jasoet/gopki/commit/9ff809681667afbf5cea7c0d1b418f66523adf15))
* **docs:** add MIT license and update README with table of contents and feature examples ([9e5a9cf](https://github.com/jasoet/gopki/commit/9e5a9cff5db26731a408731b553426db7a7f0097))
* **taskfile:** add support for encryption examples and unify build configuration ([903e0f8](https://github.com/jasoet/gopki/commit/903e0f88ed8ff416c0fe74f6bd5fab56db735f50))

## [1.11.0](https://github.com/jasoet/gopki/compare/v1.10.0...v1.11.0) (2025-09-17)


### ✨ Features

* **keypair:** implement type-safe key parsing and format-specific file handling ([7fce986](https://github.com/jasoet/gopki/commit/7fce98620325407bcbc3570f341a7b2f1844f500))
* **keypair:** introduce KeyPairManager and type-safe keypair operations ([d789669](https://github.com/jasoet/gopki/commit/d7896699d87d452464b8a6c4ede076971ffe9289))


### ♻️ Refactoring

* **keypair:** rename KeyPairManager to Manager for clarity ([b6ce54b](https://github.com/jasoet/gopki/commit/b6ce54bc09989204ba4e1a3bf11e410887caeb00))
* **keypair:** utilize explicit private/public key generics in Manager ([ce72bbe](https://github.com/jasoet/gopki/commit/ce72bbec555349473a44713bdce9dde61f96b2cc))


### ✅ Tests

* **keypair:** add comprehensive unit tests and benchmarks for Manager ([c3f4a1f](https://github.com/jasoet/gopki/commit/c3f4a1f4294d02f34b406088d4d7cee432060089))
* **keypair:** enhance static function tests to cover all algorithms ([5c9e978](https://github.com/jasoet/gopki/commit/5c9e978fbe0f2e26646105a416f05f3aadb08abb))


### 🔧 Miscellaneous

* remove deprecated DER and PEM format handling code ([8d3c505](https://github.com/jasoet/gopki/commit/8d3c505394fc834af1b67f99536e63a2449f7108))
* remove outdated keypair test files and associated functionality ([e769601](https://github.com/jasoet/gopki/commit/e769601af48c91238c4402e488e5d8fc309a4844))

## [1.10.0](https://github.com/jasoet/gopki/compare/v1.9.0...v1.10.0) (2025-09-17)


### ✨ Features

* **format:** implement format-specific generic type system with comprehensive tests ([6591b70](https://github.com/jasoet/gopki/commit/6591b70caf95591bab406953766f915c8b2bb740))
* **keypair:** add DER and SSH format support for RSA, ECDSA, and Ed25519 ([879df25](https://github.com/jasoet/gopki/commit/879df2588c4527fb6b169fe21471a73311b7a320)), closes [PKCS#8](https://github.com/jasoet/PKCS/issues/8)

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
