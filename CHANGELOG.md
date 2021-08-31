# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.1.0] - 2021-08-31

### Changed
- Removed deprecated "DecryptData" methods.
- Ensured deletion of sensitive data.

## [6.0.0] - 2021-08-30

### Changed
- Removed deprecated "DecryptData" methods.
- Some refactoring in SplitKeyEncryption.

## [5.5.1] - 2021-08-13

### Changed
- Made algorithm for finding optimal SecureRandom class more robust and added JUnit test for it.

## [5.5.0] - 2021-05-28

### Changed
- Refactored ProtectedByteArray. It now uses a masker so there is no need to store an additional obfuscation array, which means that ShuffledByteArray is gone. The new ProtectedByteArray is the old ShuffledByteArray with a masker. This obfuscates protected data better in memory dumps.

## [5.4.3] - 2021-05-17

### Changed
- Simplified byte to char mapping in Base32Encoding.

## [5.4.2] - 2021-01-04

### Changed
- Corrected names of some incorrectly named methods and variables.

## [5.4.1] - 2020-12-30

### Changed
- Removed synchronizations where not necessary.

## [5.4.0] - 2020-12-29

### Changed
- Made methods thread-safe.

## [5.3.1] - 2020-12-04

### Changed
- Fixed several SonarLint findings.

## [5.3.0] - 2020-11-13

### Added
- Added CHANGELOG.md

### Changed
- New format `6` introduced. It uses a custom form of Base32 encoding for the encrypted string.
- Documented new format in `README.md`.
- Changed `README.md` to use one line per sentence.
