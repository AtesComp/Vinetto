# -*- coding: UTF-8 -*-
"""
module utils.py
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumb Database files
 Copyright (C) 2005, 2006 by Michel Roukine
 Copyright (C) 2019-2020 by Keven L. Ates

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
file_micro = "2"


OS_WIN_ESEDB_VISTA  = "ProgramData/"
OS_WIN_ESEDB_XP     = "All Users/Application Data/"
OS_WIN_ESEBD_COMMON = "Microsoft/Search/Data/Applications/Windows/Windows.edb"

OS_WIN_USERS_XP       = "Documents and Settings/"
OS_WIN_USERS_VISTA    = "Users/"
OS_WIN_THUMBCACHE_DIR = "AppData/Local/Microsoft/Windows/Explorer/"


THUMBS_SUBDIR    = ".thumbs"
THUMBS_FILE_URLS = "urls.txt"

THUMBS_TYPE_OLE  = 0
THUMBS_TYPE_CMMM = 1
THUMBS_TYPE_IMMM = 2

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
OLE_LAST_BLOCK = 0xFFFFFFFE  # unsigned -2  Marks Last Sector
OLE_NONE_BLOCK = 0xFFFFFFFF  # unsigned -1  Marks Unused Sector

# OLE_BLOCK_TYPES: (Stream Types)
#   0x00 = empty,
#   0x01 = storage,
#   0x02 = stream,
#   0x03 = lock bytes,
#   0x04 = property,
#   0x05 = root storage
OLE_BLOCK_TYPES = ["Empty", "Storage", "Stream", "LockBytes", "Property", "Root"]


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

#
#  Windows Thumbcache location:
#    Windows 7, 8, 10:
#      C:\Users\*\AppData\Local\Microsoft\Windows\Explorer
#
#  Windows Search (Windows.edb) Extensible Storage Engine (ESE) database:
#    Windows 7:
#      C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
#
#    The Windows.edb stores the ThumbnailCacheID as part of its metadata for indexed files.
#    Uses ESEDB library pyesedb to read the EDB file.
#
ESEDB_FILE      = None  # Opened Windows.edb or equivalent user specified file
ESEDB_TABLE     = None  # Opened SystemIndex_0A or SystemIndex_PropertyStore table from ESEDB_FILE
ESEDB_REC_LIST  = None  # Image records from ESEDB_TABLE

ESEDB_ICOL_NAMES = {
    # 'x' - bstr  == (Large) Binary Data
    # 's' - str   == (Large) Text
    # 'i' - int   == Integer (32/16/8)-bit (un)signed
    # 'b' - bool  == Boolean or Boolean Flags
    # 'f' - float == Floating Point (Double Precision) (64/32-bit)
    # 'd' - date  == Binary Data converted to Formatted UTC Time

    # ESEDB Data Types:
    # BINARY_DATA = 9
    # BOOLEAN = 1
    # CURRENCY = 5
    # DATE_TIME = 8
    # DOUBLE_64BIT = 7
    # FLOAT_32BIT = 6
    # GUID = 16
    # INTEGER_16BIT_SIGNED = 3
    # INTEGER_16BIT_UNSIGNED = 17
    # INTEGER_32BIT_SIGNED = 4
    # INTEGER_32BIT_UNSIGNED = 14
    # INTEGER_64BIT_SIGNED = 15
    # INTEGER_8BIT_UNSIGNED = 2
    # LARGE_BINARY_DATA = 11
    # LARGE_TEXT = 12
    # NULL = 0
    # SUPER_LARGE_VALUE = 13
    # TEXT = 10

    # Key:   (Column Text,                             Type,      Display Text   )
    "TCID":  ("System_ThumbnailCacheId",                'x', "    ThumbCacheID: "),  # 4670-System_ThumbnailCacheId
    "MIME":  ("System_MIMEType",                        's', "        MimeType: "),  # 4468-System_MIMEType
    "CTYPE": ("System_ContentType",                     's', "     ContentType: "),  # 4349-System_ContentType
    "ITT":   ("System_ItemTypeText",                    's', "    ItemTypeText: "),  # 5-System_ItemTypeText
    "ITYPE": ("System_ItemType",                        's', "        ItemType: "),  # 4446-System_ItemType
    "FEXT":  ("System_FileExtension",                   's', "         FileExt: "),  # 4388-System_FileExtension
    "FNAME": ("System_FileName",                        's', "        FileName: "),  # 11-System_FileName
    "INAME": ("System_ItemName",                        's', "        ItemName: "),  # 4438-System_ItemName
    "IND":   ("System_ItemNameDisplay",                 's', " ItemNameDisplay: "),  # 4439-System_ItemNameDisplay
    "PNAME": ("System_ParsingName",                     's', "       ParseType: "),  # 4561-System_ParsingName
    "INDWE": ("System_ItemNameDisplayWithoutExtension", 's', "   ItemNameWOExt: "),  # 4440-System_ItemNameDisplayWithoutExtension
    "IPD":   ("System_ItemPathDisplay",                 's', "        ItemPath: "),  # 4443-System_ItemPathDisplay
    "IURL":  ("System_ItemUrl",                         's', "         ItemUrl: "),  # 33-System_ItemUrl
    "IPDN":  ("System_ItemPathDisplayNarrow",           's', "       ItemPathN: "),  # 4444-System_ItemPathDisplayNarrow
    "IFPD":  ("System_ItemFolderPathDisplay",           's', "  ItemFolderPath: "),  # 4436-System_ItemFolderPathDisplay
    "IFND":  ("System_ItemFolderNameDisplay",           's', "  ItemFolderName: "),  # 3-System_ItemFolderNameDisplay
    "IFPDN": ("System_ItemFolderPathDisplayNarrow",     's', " ItemFolderPathN: "),  # 4437-System_ItemFolderPathDisplayNarrow
    "DATEM": ("System_DateModified",                    'd', "    DateModified: "),  # 15F-System_DateModified
    "DATEC": ("System_DateCreated",                     'd', "     DateCreated: "),  # 16F-System_DateCreated
    "DATEA": ("System_DateAccessed",                    'd', "    DateAccessed: "),  # 17F-System_DateAccessed
    "DATEI": ("System_DateImported",                    'd', "    DateImported: "),  # 4361-System_DateImported
    "IDATE": ("System_ItemDate",                        'd', "        ItemDate: "),  # 4434-System_ItemDate
    "DDC":   ("System_Document_DateCreated",            'd', "  DateDocCreated: "),  # 4367-System_Document_DateCreated
    "DDS":   ("System_Document_DateSaved",              'd', "    DateDocSaved: "),  # 4369-System_Document_DateSaved
    "KIND":  ("System_Kind",                            'x', "           Kind#: "),  # 4452-System_Kind
    "KINDT": ("System_KindText",                        's', "        KindText: "),  # 4453-System_KindText
    "IDIM":  ("System_Image_Dimensions",                's', "       ImageDims: "),  # 4416-System_Image_Dimensions
    "IHSZ":  ("System_Image_HorizontalSize",            'i', "   ImageHorzSize: "),  # 4418-System_Image_HorizontalSize
    "IVSZ":  ("System_Image_VerticalSize",              'i', "   ImageVertSize: "),  # 4420-System_Image_VerticalSize
    "IHRES": ("System_Image_HorizontalResolution",      'f', "    ImageHorzRes: "),  # 4417-System_Image_HorizontalResolution
    "IVRES": ("System_Image_VerticalResolution",        'f', "    ImageVertRes: "),  # 4419-System_Image_VerticalResolution
    "IBITD": ("System_Image_BitDepth",                  'i', "   ImageBitDepth: "),  # 4413-System_Image_BitDepth

    "FOWN":  ("System_FileOwner",                       's', "       FileOwner: "),  # 4392-System_FileOwner
    "SIZE":  ("System_Size",                            'x', "        FileSize: "),  # 13F-System_Size
    "IOMD5": ("InvertedOnlyMD5",                        'x', " InvertedOnlyMD5: "),  # 0F-InvertedOnlyMD5
}

ESEDB_ICOL = {}
for key in ESEDB_ICOL_NAMES.keys():
    ESEDB_ICOL[key] = None

ARGS = None
EXIT_CODE = 0


