# Changelog
All notable changes to Ruby Dragon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.1.0] - 2022-01-26
### Added
 - Kotlin script capability (uses Kotlin 1.6.0)

### Removed
 - Support for Ghidra 9.2.4 due to new BouncyCastle dependency.

## [1.0.3] - 2022-01-05
### Changed
 - Upgrade to Jruby 9.3.2.0 (Ruby 2.6.8)


## [1.0.2] - 2021-10-03
### Fixed
 - Expand class lookup warning to also appear for Ghidra 10.0.4.


## [1.0.1] - 2021-09-27
### Fixed
 - Add warning and patch `support/launch.properties` file for Ghidra 10.0.3
   problems with class lookups.


### Changed
 - Upgrade to JRuby 9.3.0.0 (Ruby 2.6.8)


## [1.0.0] - 2021-08-29
### Added
 - Add headless support to example scripts.
 - Add script argument support to Ruby scripts.


## [0.2.0] - 2021-07-06
### Added
 - Example Ruby scripts.
 - Interactive Clojure interpreter (uses Clojure 1.10.3).
 - Clojure script capability (uses Clojure 1.10.3).


### Changed
 - Upgrade to JRuby 9.2.19.0 (Ruby 2.5.8).


## [0.1.0] - 2021-03-08
### Added
 - Interactive Ruby interpreter.
 - Ruby script capability.
 - Global variables reflecting current program state.

