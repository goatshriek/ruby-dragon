# Changelog
All notable changes to Ruby Dragon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [5.0.0] - 2025-04-24
### Changed
 - Upgrade to JRuby 10.0.0.0 (Ruby 3.4.2)
 - Upgrade to Groovy 4.0.26
 - Upgrade to Kotlin 2.1.20


## [4.2.0] - 2025-02-14
### Changed
 - Upgrade to JRuby 9.4.12.0 (Ruby 3.1.4)
 - Upgrade to Groovy 4.0.25
 - Upgrade to Kotlin 2.1.10

### Deprecated
 - `DragonPlugin.getCompletions(String cmd)` in favor of
   `DragonPlugin.getCompletions(String cmd, int caretPos)`. This mirrors the
   deprecation of the same method in
   `ghidra.app.plugin.core.interpreter.InterpreterConnection`.


## [4.1.0] - 2024-11-08
### Changed
 - Upgrade to JRuby 9.4.9.0 (Ruby 3.1.4)
 - Upgrade to Clojure 1.12.0
 - Upgrade to Groovy 4.0.23
 - Upgrade to Kotlin 2.0.21


## [4.0.0] - 2024-07-08
### Added
 - Current function, data, and instruction interpreter variables.

### Changed
 - Upgrade to JRuby 9.4.8.0 (Ruby 3.1.4)
 - Upgrade to Clojure 1.11.3
 - Upgrade to Groovy 4.0.22
 - Upgrade to Kotlin 2.0.0
 
### Removed
 - Warnings and `launch.properties` files for broken JRuby support in older
   versions of Ghidra.


## [3.3.0] - 2024-03-28
### Changed
 - Upgrade to JRuby 9.4.6.0 (Ruby 3.1.4)
 - Upgrade to Clojure 1.11.2
 - Upgrade to Groovy 4.0.20
 - Upgrade to Kotlin 1.9.23


## [3.2.0] - 2023-12-24
### Changed
 - Upgrade to JRuby 9.4.5.0 (Ruby 3.1.4)
 - Upgrade to Groovy 4.0.17
 - Upgrade to Kotlin 1.9.22


## [3.1.0] - 2023-09-14
### Added
 - Loading banners with load time and language version to all interactive
   interpreters.

### Changed
 - Automatic class import now defaults to off instead of on.
 - All interactive interpreters are now lazily created.
 - Upgrade to Groovy 4.0.14
 - Upgrade to Kotlin 1.9.10


## [3.0.0] - 2023-07-13
### Added
 - Toolbar icons for each interpreter.

### Changed
 - Upgrade to JRuby 9.4.3.0 (Ruby 3.1.4)
 - Upgrade to Groovy 4.0.13
 - Upgrade to Kotlin 1.9.0


## [2.3.0] - 2023-06-04
### Changed
 - Upgrade to Groovy 4.0.12
 - Upgrade to Kotlin 1.8.21


## [2.2.0] - 2023-03-15
### Added
 - Automatic class import option for all interpreters.

### Changed
 - Upgrade to Groovy 4.0.9
 - Upgrade to JRuby 9.3.10.0
 - Upgrade to Kotlin 1.8.10


## [2.1.0] - 2022-11-20
### Added
 - Groovy script capability (uses Groovy 4.0.6)

### Fixed
 - F1 now properly resolves help page for interpreter under pointer


## [2.0.0] - 2022-11-06
### Changed
 - Upgrade to JRuby 9.3.9.0 (Ruby 2.6.8)
 - Upgrade to Kotlin 1.7.20
 - Change of exceptions thrown by the `getScriptInstance` methods has changed
   as a result of Ghidra 10.2 API changes


## [1.3.0] - 2022-07-29
### Added
 - JShell interactive interpreter
 - currentAPI interpreter variables with `FlatProgramAPI` instance


## [1.2.0] - 2022-06-11
### Changed
 - Upgrade to JRuby 9.3.4.0 (Ruby 2.6.8)
 - Upgrade to Clojure 1.11.1
 - Upgrade to Kotlin 1.7.0
 - Dependencies are now managed via Gradle


## [1.1.0] - 2022-02-06
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

