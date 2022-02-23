# -*- coding: UTF-8 -*-
"""
module utils.py
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumb Database files
 Copyright (C) 2005, 2006 by Michel Roukine
 Copyright (C) 2019-2022 by Keven L. Ates

This file is part of Vinetto.

 Vinetto is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as published
 by the Free Software Foundation; either version 2 of the License, or (at
 your option) any later version.

 Vinetto is distributed in the hope that it will be
 useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License along
 with the vinetto package; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

-----------------------------------------------------------------------------
"""


file_major = "0"
file_minor = "1"
file_micro = "10"


OS_WIN_ESEDB_VISTA  = "ProgramData/"
OS_WIN_ESEDB_XP     = "All Users/Application Data/"
OS_WIN_ESEBD_COMMON = "Microsoft/Search/Data/Applications/Windows/"
OS_WIN_ESEBD_FILE   = "Windows.edb"

OS_WIN_USERS_XP       = "Documents and Settings/"
OS_WIN_USERS_VISTA    = "Users/"
OS_WIN_THUMBCACHE_DIR = "AppData/Local/Microsoft/Windows/Explorer/"


THUMBS_SUBDIR    = ".thumbs"
THUMBS_FILE_SYMS = "symlinks.log"

THUMBS_TYPE_OLE  = 0
THUMBS_TYPE_CMMM = 1
THUMBS_TYPE_IMMM = 2

THUMBS_TYPE_OLE_PIL = None  # No attempt to load PIL
THUMBS_TYPE_OLE_PIL_TYPE1_HEADER   = None
THUMBS_TYPE_OLE_PIL_TYPE1_QUANTIZE = None
THUMBS_TYPE_OLE_PIL_TYPE1_HUFFMAN  = None

THUMBS_SIG_OLE =  bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")  # Standard Sig for OLE2 Thumbs.db file
THUMBS_SIG_OLEB = bytearray(b"\x0e\x11\xfc\x0d\xd0\xcf\x11\xe0")  # Older Beta Sig for OLE2 Thumbs.db file
THUMBS_SIG_CMMM = bytearray(b"CMMM")  # Standard Sig for Thumbcache_*.db files
THUMBS_SIG_IMMM = bytearray(b"IMMM")  # Standard Sig for Thumbcache_*.db Index files

THUMBS_FILE_TYPES = ["OLE (Thumb.db)", "CMMM (Thumbcache_*.db)", "IMMM (Thumbcache_*.db)"]

# Sectors Allocation Table (SAT) Sectors
# --------------------
# When taken together as a single stream the collection of FAT sectors define the
# status and linkage of every sector in the file. Each entry in the SAT is 4 bytes
# in length and contains the sector number of the next sector in a SAT chain or
# one of the following special values:
#
# FREESECT   (0xFFFFFFFF, -1) – denotes an unused sector
# ENDOFCHAIN (0xFFFFFFFE, -2) – marks the last sector in a FAT chain
# SATSECT    (0xFFFFFFFD, -3) – marks a sector used to store part of the SAT
# DISSECT    (0xFFFFFFFC, -4) – marks a sector used to store part of the DISAT
#
# Range Lock Sector
# --------------------
# The Range Lock Sector must exist in files greater than 2GB in size, and must not
# exist in files smaller than 2GB. The Range Lock Sector must contain the byte
# range 0x7FFFFF00 to 0x7FFFFFFF in the file. This area is reserved by Microsoft's
# COM implementation for storing byte-range locking information for concurrent
# access.
OLE_PDIS_BLOCK = 0xFFFFFFFC  # unsigned -4  Marks DISAT Part Sector
OLE_PART_BLOCK = 0xFFFFFFFD  # unsigned -3  Marks SAT Part Sector
OLE_LAST_BLOCK = 0xFFFFFFFE  # unsigned -2  Marks Last Sector (no more!)
OLE_NONE_BLOCK = 0xFFFFFFFF  # unsigned -1  Marks Unused Sector

# OLE_BLOCK_TYPES: (Stream Types)
#   0x00 = empty,
#   0x01 = storage,
#   0x02 = stream,
#   0x03 = lock bytes,
#   0x04 = property,
#   0x05 = root storage
OLE_BLOCK_TYPES = ["Empty", "Storage", "Stream", "LockBytes", "Property", "Root"]

# Endian Byte Order
LIL_ENDIAN = b"\xfe\xff"
BIG_ENDIAN = b"\xff\xfe"

# JPEG JFIF Block Markers
# --------------------
# The JPEG JFIF Markers denote JPEG data blocks that define the image.
#Marker Code Name
#------ ---- --------------------
#FF D8  SOI  Start Of Image
#FF E0  APP0 JFIF File
#FF DB  DQT  Define Quantization Table
#FF C0  SOF  Start Of Frame
#FF C4  DHT  Define Huffman Table
#FF DA  SOS  Start Of Scan
#FF D9  EOI  End Of Image
#
#JFIF Header [20 bytes]
#------------------------------------------------------------
#BYTE SOI[2]         FF D8
#BYTE APP[2]         FF E0
#BYTE Length[2]      APP Length after marker
#BYTE Identifier[5]  "JFIF\0"
#BYTE Version[2]     Major, Minor
#BYTE Units          0 (none), 1 (pix/inch), 2 (pix/cm)
#BYTE X_Density[2]   Horiz Pixel Density
#BYTE Y_Density[2]   Vert  Pixel Density
#BYTE Width          Thumbnail width, if any
#BYTE Height         Thumbnail height, if any
JPEG_SOI  = b"\xff\xd8"
JPEG_APP0 = b"\xff\xe0"
JPEG_DQT  = b"\xff\xdb"
JPEG_SOF  = b"\xff\xc0"
JPEG_DHT  = b"\xff\xc4"
JPEG_SOS  = b"\xff\xda"
JPEG_EOI  = b"\xff\xd9"

TC_FORMAT_TYPE = { "Windows Vista" : 0x14,
                   "Windows 7"     : 0x15,
                   "Windows 8"     : 0x1A,
                   "Windows 8 v2"  : 0x1C,
                   "Windows 8 v3"  : 0x1E,
                   "Windows 8.1"   : 0x1F,
                   "Windows 10"    : 0x20,
                 }
TC_FORMAT_TO_CACHE = { 0x14 : 0,  # Keys relate to TC_FORMAT_TYPE
                       0x15 : 0,  # Values relate to index of TC_CACHE_TYPE
                       0x1A : 1,  #
                       0x1C : 1,  # Therefore, the declared format type
                       0x1E : 1,  # controls the indication of the valid
                       0x1F : 2,  # available cache types the file may
                       0x20 : 3,  # represent.
                     }
# Cache Types that the file "thumbcache_XXX.db" may represent
#            Index: .> 00      01      02      03      04      05      06      07      08      09      0A      0B      0C                0D
#                    v
TC_CACHE_TYPE = (
                  # 0 -- Windows Vista & 7 ------------------
                  (   "32",   "96",  "256", "1024",   "sr" ),
                  # 1 -- Windows 8, 8 v2, & 8 v3 ------------
                  (   "16",   "32",   "48",   "96",  "256", "1024",   "sr", "wide", "exif" ),
                  # 2 -- Windows 8.1 ------------------------
                  (   "16",   "32",   "48",   "96"   "256", "1024", "1600",   "sr", "wide", "exif", "wide_alternate" ),
                  # 3 -- Windows 10 -------------------------
                  (   "16",   "32",   "48",   "96",  "256",  "768", "1280", "1920", "2560",   "sr", "wide", "exif", "wide_alternate", "custom_stream" ),
                )
TC_CACHE_ALL = ( "16",   "32",   "48",   "96",  "256", "768", "1024", "1280", "1600", "1920", "2560",   "sr",  "idx", "wide", "exif", "wide_alternate", "custom_stream" )
TC_CACHE_ALL_DISPLAY = ( "16",   "32",   "48",   "96",  "256", "768", "1024", "1280", "1600", "1920", "2560",   "sr",  "idx", "wide", "exif", "walt", "cust" )

#
#  Windows Thumbcache location:
#    Windows 7, 8, 10:
#      C:\Users\*\AppData\Local\Microsoft\Windows\Explorer
#

ESEDB = None

LIST_PLACEHOLDER = ["", ""]

STR_SEP = " ------------------------------------------------------"

HTTP_REPORT = None

ARGS = None
