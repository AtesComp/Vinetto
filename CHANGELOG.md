# Changelog

All notable changes to this project will be documented in this file.

## [Released]

## [0.8.4] - 2019-11-xx

### Added

- MD5 switch "--md5" to force MD5 calculation as per previous behavior
- MD5 switch "--nomd5" to force no MD5 calculation
- Mode switch "--mode" with "d" (directory) and "r" (recursive directory) processing looks for common thumbnail file names to process
- New thumbcache_*.db file processing determined by the file signatures

### Changed

- The vinetto python file renamed to vinetto.py and added to the vinetto package
- Vinetto global code was restructured into various functions and a main() entry point
- The setup.py was modified to auto-create the "vinetto" executable on an entry point in vinetto.py
- Default MD5 calculation behavior from always to only when the file size is less than 500 MiB
- Due to possible large file processing issues, file processing uses seek() and read() instead of loading entire file into memory
- Signed integer value input to unsigned integer value input and related processing
- Corrected symlink processing dependency on Catalog entries and Stream Id
- Corrected symlink links relative to image
- Restructured and renamed many functions
- Moved time conversion function (Win32 to Python) from vinetto to vinutils
- All time values converted to UTC
- Reformatted header block to clarify and condense information
- Reformatted HTML report to clarify and condense information

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
