# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
