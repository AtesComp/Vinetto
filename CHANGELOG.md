# Changelog

All notable changes to this project will be documented in this file.

## [0.9.4] - 2020-01-31 (DEVELOPEMENT)

### Added

- Extreme Makeover: Added Error Classes
- Documented Verbose Modes (including Quiet) in help

### Changed

- Extreme Makeover: changed error coding to raise errors managed at main for exit status
- Updated exit codes -- consolidated and renamed
- Tweaked verbosity code; previously added Level -1 for -q option

## [0.9.3] - 2020-01-31 (DEVELOPEMENT)

### Added

- Extreme Makeover: More new files to contain Thumbnail File processing (to be converted to classes)

### Changed

- Extreme Makeover: Restructured Thumbnail File processing to be consistent between file types
- Updated code relationship between "catalog", symlink, and HTML processing
- More IMMM process tweaking for Windows versions
- Overhauled HTML Report structure and coding

## [0.9.2] - 2020-01-23 (DEVELOPEMENT)

### Changed

- IMMM files: Corrected processing for Windows 10
- IMMM Output Verbosity: controlled tabular output based on verbosity Levels 0, 1, 2 or more

## [0.9.1] - 2020-01-22 (DEVELOPEMENT)

### Added

- ESEDB Explorer: Explore extracted image related ESEDB data -- omitting the input file allows exploring the -e file's extracted data
- Verbosity: -v, --verbose option -- output for -v levels (currently only level 1) prints info messages + extra tablular output

### Changed

- output for -q surpresses all output except errors
- output for normal (no -q or -v option == verbose level 0) prints warning messages + standard tablular output
- functionalized some redundant code
- extract and hold all image related ESEDB data once and close ESEDB file instead of redundantly querying ESEDB records
- moved some functions to util module

## [0.9.0] - 2020-01-21 (DEVELOPEMENT)

### Added

- Extreme Makeover: New class files to contain custom dictionaries to manage catalogs and streams
- All known stream types (Empty, Storage, Stream, LockBytes, Property, Root) are reported

### Changed

- Extreme Makeover: Contained existing functionality in classes as applicable
- Restructured and renamed existing files
- Use cache counter for "catalog" ID on Thumbcache_*.db entries

## [0.8.9] - 2020-01-10 (DEVELOPEMENT)

### Changed

- Restructured globals
- Revised file versioning
- Claimed authorship due to extensive restructuring
- Allow for multiple maintainers

## [0.8.8] - 2020-01-09 (DEVELOPEMENT)

### Added

- ESEDB data expanded to include additional related columns
- Added file extension processing in image row display for HTML report

### Changed

- Streamlined ESEDB related processing
- Corrected and modified ESEDB processing and output
- Corrected and modified image row display for HTML report

## [0.8.7] - 2020-01-07 (DEVELOPEMENT)

### Changed

- Create symlinks directory early and once
- Thumbcache IDs can be in both Thumbs.db and Thumbcache_#.db files
- Symlink directory not dependent on Stream ID or Thumbcache ID
- Symlink can be created on both Stream ID and Thumbcache ID
- Http Report changes for thumbcache_#.db files
- Consolidated version information for common use by setup.py and program
- Mapped catalog entry for Thumb Cache ID found in ESEDB

## [0.8.6] - 2020-01-03 (DEVELOPEMENT)

### Changed

- Removed dependency on "python-magic"
- Preliminary working process for thumbcache_#.db files
- Preliminary working process for ESEDB enhancement
- Minor corrections to the symlink process.

## [0.8.5] - 2019-12-27 (DEVELOPEMENT)

### Added

- EDB file switch "-e, --edb" to provide an input EDB file (Windows.edb) to examine for original thumbnail filenames
- Import python ESEDB library, version dependent (2.7 or 3.7)
- Mode switch option "f" (file, default mode) to provide the default operating mode
- Mode switch option "a" (automatic) processing to analize given directory as a Windows Vista+ partition for default locations of thumbcache_*.db and Windows.edb files
- New HTML Report functions to process thumbcache_#.db files

### Changed

- HTML Report to include processing for thumbcache_#.db files
- Utilities to include processing for thumbcache_#.db files
- Streamlined processing stats

## [0.8.4] - 2019-11-15 (DEVELOPEMENT)

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

## [0.8.0] - 2019-10-28 (RELEASED)

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
