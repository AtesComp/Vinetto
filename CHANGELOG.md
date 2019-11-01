# Changelog

All notable changes to this project will be documented in this file.

## [Released]

## [0.8.0] - 2019-10-28

### Added

- Exit codes expanded to indicate specific error
- Added checks for newer Thumbnail file structures
- Control endian-ness of thumbnail data

### Changed

- Updated code to be Python 3 compliant, should still work under Python 2
- Overhauled parameter parsing
- Updated help
- Overhauled symlink creation for HTML report to be OS agnostic
- Updated versioning
- Reordered required module loading
- Loading and unloading specific modules only when needed (such as PIL Image)
- Thumbnail information restructured for output
- Many variables renamed for clarity
- Updated unicode processing
