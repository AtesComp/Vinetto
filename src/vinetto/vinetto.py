#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumbs.db files
 Copyright (C) 2005, 2006 by Michel Roukine

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

__major__ = "0"
__minor__ = "8"
__micro__ = "5"
__maintainer__ = "Keven L. Ates"
__author__ = "Michel Roukine"
__location__ = "https://github.com/AtesComp/Vinetto"

import sys
import os
import fnmatch
import errno
import argparse
from io import StringIO
from struct import unpack
from binascii import hexlify

import magic

import vinetto.vinreport
from vinetto.vinutils import LAST_BLOCK, NONE_BLOCK, \
                             addCatalogEntry, countCatalogEntry, countThumbnails, \
                             getStreamFileName, getRawFileName, \
                             isCatalogOutOfSequence, isStreamsOutOfSequence, \
                             addStreamIdToStreams, addFileNameToStreams, \
                             extractStats, convertToPyTime, getFormattedTimeUTC
from pkg_resources import resource_filename

PROG = os.path.basename(__file__).capitalize()

THUMBS_SUBDIR = ".thumbs"

THUMBS_TYPE_OLE  = 1
THUMBS_TYPE_CMMM = 2
THUMBS_TYPE_IMMM = 3

#
# pps_type:
#    Stream Types: 0x00 = empty,
#                  0x01 = storage,
#                  0x02 = stream,
#                  0x03 = lock bytes,
#                  0x04 = property,
#                  0x05 = root storage
#

PPS_TYPES = ["Empty", "Storage", "Stream", "LockBytes", "Property", "Root"]


TC_FORMAT_TYPE = { "Windows Vista" : 0x14,
                   "Windows 7"     : 0x15,
                   "Windows 8"     : 0x1A,
                   "Windows 8 v2"  : 0x1C,
                   "Windows 8 v3"  : 0x1E,
                   "Windows 8.1"   : 0x1F,
                   "Windows 10"    : 0x20,
                 }
TC_FORMAT_TO_CACHE = { 0x14 : 0, # Keys relate to TC_FORMAT_TYPE
                       0x15 : 0, # Values relate to index of TC_CACHE_TYPE
                       0x1A : 1, #
                       0x1C : 1, # Therefore, the declared format type
                       0x1E : 1, # controls the indication of the valid
                       0x1F : 2, # available cache types the file may
                       0x20 : 3, # represent.
                     }
# Cache Types that the file "thumbcache_XXX.db" may represent
#            Index: .> 00      01      02      03      04      05      06      07      08      09      0A      0B      0C                0D
#                    v
TC_CACHE_TYPE = ( # 0 -- Windows Vista & 7 ------------------
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
ESEDB_FILE = None
ESEDB_TABLE = None
ESEDB_ICOL_TCI = None
ESEDB_ICOL_IPD = None
ESEDB_ICOL_IU = None

ARGS = None
EXIT_CODE = 0

IMAGE_TYPE_1_HEADER   = None
IMAGE_TYPE_1_QUANTIZE = None
IMAGE_TYPE_1_HUFFMAN  = None

# Magic IDs for images...
IMAGE_TYPE_BMP  = 0x424D                # BM
IMAGE_TYPE_JPEG = 0xFFD8FFE0            # ....
IMAGE_TYPE_PNG  = 0x89504E470D0A1A0A    # .PNG\n\r\sub\r

HTTP_REPORT = None

STR_SEP = " ------------------------------------------------------"

def getArgs():
    # Return arguments passed to vinetto on the command line.

    descstr = PROG + " - The Thumbnail File Parser"
    epilogstr = (
        "Operating Mode Notes:\n" +
        "  Using the mode switch (-m, --mode) causes the input to be treated differently\n" +
        "  based on the mode selected\n" +
        "  File      (f): DEFAULT\n" +
        "    Use the input as a location to an individual thumbnail file to process\n" +
        "  Directory (d):\n" +
        "    Use the input as a directory containing individual thumbnail files where\n" +
        "    each file is automatically iterated for processing\n" +
        "  Recursive (r):\n" +
        "    Use the input as a BASE directory from which it and subdirectories are\n" +
        "    recursively searched for individual thumbnail files for processing\n" +
        "  Automatic (a):\n" +
        "    Use the input as a BASE directory of a partition to examine default\n" +
        "    locations for relevant thumbnail files to process\n" +
        "      Thumbcache Files:\n" +
        "        BASE/Users/*/AppData/Local/Microsoft/Windows/Explorer\n" +
        "          where '*' are user directories iterated automatically\n" +
        "      Windows.edb File:\n" +
        "        BASE/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb\n" +
        "    When the EDBFILE (-e, -edbfile switch) is given, it overrides the automated\n" +
        "    location\n" +
        "\n"
        "--- " + PROG + " " + __major__ + "." + __minor__ + "." + __micro__ + " ---\n" +
        "Based on the original Vinetto by " + __author__ + "\n" +
        "Updated by " + __maintainer__ + "\n" +
        PROG + " is open source software\n" +
        "  See: " + __location__
        )

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=descstr, epilog=epilogstr)
    parser.add_argument("-e", "--edb", dest="edbfile", metavar="EDBFILE",
                        help="examine EDBFILE for original thumbnail filenames")
    parser.add_argument("-H", "--htmlrep", action="store_true", dest="htmlrep",
                        help="write html report to DIR (requires option -o)")
    parser.add_argument("-m", "--mode", dest="mode", choices=["f", "d", "r", "a"], default="f",
                        help=("operating mode: \"f\", \"d\", \"r\", or \"a\"\n" +
                              "  where \"f\" indicates single file processing\n" +
                              "        \"d\" indicates directory processing\n" +
                              "        \"r\" indicates recursive directory processing from a\n" +
                              "              starting directory\n" +
                              "        \"a\" indicates automatic processing using well known\n" +
                              "              directories starting from a base directory"))
    parser.add_argument("--md5", action="store_true", dest="md5force",
                        help=("force the MD5 hash value calculation for an input file\n" +
                              "Normally, the MD5 is calculated when a file is less than\n" +
                              "0.5 GiB in size\n" +
                              "NOTE: --nomd5 overrides --md5"))
    parser.add_argument("--nomd5", action="store_true", dest="md5never",
                        help=("skip the MD5 hash value calculation for an input file"))
    parser.add_argument("-o", "--outdir", dest="outdir", metavar="DIR",
                        help="write thumbnails to DIR")
    parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                        help="quiet output")
    parser.add_argument("-s", "--symlinks", action="store_true", dest="symlinks",
                        help=("create symlink from the the image realname to the numbered name\n" +
                              "in DIR/" + THUMBS_SUBDIR + " (requires option -o)\n" +
                              "NOTE: A Catalog containing the realname must exist for this\n" +
                              "      option to produce results OR a Windows.edb must be given\n" +
                              "      (-e) to find and extract possible file names"))
    parser.add_argument("-U", "--utf8", action="store_true", dest="utf8",
                        help="use utf8 encodings")
    parser.add_argument("--version", action="version", version=epilogstr)
    parser.add_argument("infile",
                        help=("depending on operating mode, either a location to a thumbnail\n" +
                              " file (\"Thumb.db\" or similar) or a directory"))
    pargs = parser.parse_args()

    if (pargs.infile == None):
        parser.error("No input file or directory specified")

    if (pargs.outdir == None):
        if (pargs.htmlrep):
            parser.error("-H option requires -o with a directory name")
        if (pargs.symlinks):
            parser.error("-s option requires -o with a directory name")

    return (pargs)


def getEncoding():
    # What encoding do we use?
    if ARGS.utf8:
        return "utf8"
    else:
        return "iso-8859-1"


#def reencodeBytes(bytesString):
#    # Convert bytes encoded as utf-16-le to the global encoding...
#    if (sys.version_info[0] < 3):
#        return unicode(bytesString, "utf-16-le").encode(getEncoding(), "replace")
#    else:
#        return str(bytesString, "utf-16-le").encode(getEncoding(), "replace")


def decodeBytes(bytesString):
    # Convert bytes encoded as utf-16-le to standard unicode...
    if (sys.version_info[0] < 3):
        return unicode(bytesString, "utf-16-le")
    else:
        return str(bytesString, "utf-16-le")


def nextBlock(TDB, Table, indx, endian):
    # Return next block
    iSAT = indx // 128  # SAT block number to search in
    iSECT = indx % 128 # SECTor to search in the SAT block
    iOffset = Table[iSAT] * 512 + 0x200 + iSECT * 4
    TDB.seek(iOffset)
    return unpack(endian+"L", TDB.read(4))[0]


def printBlock(strName, pps_type, pps_color, pps_PDID, pps_NDID, pps_SDID, pps_CID,
               pps_userflags, pps_tsCreate, pps_tsModify, pps_SID_firstSecDir,
               pps_SID_sizeDir):
    global NONE_BLOCK

    print("          Name: %s" % strName)
    print("          Type: %d (%s)" % (pps_type, PPS_TYPES[pps_type]))
    print("         Color: %d (%s)" % (pps_color, "Black" if pps_color else "Red"))
    print("   Prev Dir ID: %s" % ("None" if (pps_PDID == NONE_BLOCK) else str(pps_PDID)))
    print("   Next Dir ID: %s" % ("None" if (pps_NDID == NONE_BLOCK) else str(pps_NDID)))
    print("   Sub  Dir ID: %s" % ("None" if (pps_SDID == NONE_BLOCK) else str(pps_SDID)))
    print("      Class ID: " + pps_CID)
    print("    User Flags: " + pps_userflags)
    print("        Create: " + pps_tsCreate)
    print("        Modify: " + pps_tsModify)
    print("       1st Sec: %d" % pps_SID_firstSecDir)
    print("          Size: %d" % pps_SID_sizeDir)
    return


def printDBHead(thumbType, sig, formatVer, cacheType, cacheOff1st, cacheOff1stAvail, cacheCount):
    print("     Signature: %s" % sig)
    if (thumbType == THUMBS_TYPE_CMMM):
        try:
            print("        Format: %d (%s)" % (formatVer, list(TC_FORMAT_TYPE.keys())[list(TC_FORMAT_TYPE.values()).index(formatVer)]))
        except ValueError:
            print("        Format: %d (%s)" % (formatVer, "Unknown Format"))
        try:
            print("          Type: %d (%s)" % (cacheType, "thumbcache_" + TC_CACHE_TYPE[TC_FORMAT_TO_CACHE[formatVer]][cacheType] + ".db"))
        except (KeyError, IndexError):
            print("          Type: %d (%s)" % (cacheType, "Unknown Type"))
        print("    Cache Info:")
        print("          Offset: %s" % ("None" if (cacheOff1st == None) else ("%d" % cacheOff1st)))
        print("   1st Available: %s" % ("None" if (cacheOff1stAvail == None) else ("%d" % cacheOff1stAvail)))
        print("           Count: %s" % ("None" if (cacheCount == None) else ("%d" % cacheCount)))
    elif (thumbType == THUMBS_TYPE_IMMM):
        try:
            print("        Format: %d (%s)" % (formatVer, list(TC_FORMAT_TYPE.keys())[list(TC_FORMAT_TYPE.values()).index(formatVer)]))
        except ValueError:
            print("        Format: %d (%s)" % (formatVer, "Unknown Format"))
        print("    Entry Info:")
        print("            Used: %s" % ("None" if (cacheOff1st == None) else ("%d" % cacheOff1st)))
        print("           Count: %s" % ("None" if (cacheCount == None) else ("%d" % cacheCount)))


def printDBCache(sig, size, iHash, strExt, idSize, padSize, dataSize, chksumD, chksumH, strID, strIPD, strIU):
    print("     Signature: %s" % sig)
    print("          Size: %d" % size)
    print("          Hash: %d" % iHash)
    if (strExt != None):
        print("     Extention: %s" % strExt)
    print("       ID Size: %d" % idSize)
    print("      Pad Size: %d" % padSize)
    print("     Data Size: %d" % dataSize)
    print(" Data Checksum: %d" % chksumD)
    print(" Head Checksum: %d" % chksumH)
    print("            ID: %s" % strID)
    print("ESEBD ItemPath: %s" % ("None" if (strIPD == None) else strIPD))
    print("ESEBD  ItemUrl: %s" % ("None" if (strIU == None) else strIU))

    return


def setupSymLink(bSymTest):
    global ARGS

    if (bSymTest and ARGS.symlinks):
        if not os.path.exists(ARGS.outdir + THUMBS_SUBDIR):
            try:
                os.mkdir(ARGS.outdir + THUMBS_SUBDIR)
            except EnvironmentError:
                sys.stderr.write(" Error: Cannot create %s\n" % ARGS.outdir + THUMBS_SUBDIR)
                EXIT_CODE = 13
                return


def symlink_force(target, link_name):
    global EXIT_CODE

    try:
        os.symlink(target, link_name)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(link_name)
            os.symlink(target, link_name)
        else:
            sys.stderr.write(" Error: Cannot create symlink %s to image %s\n" % (link_name, target))
            EXIT_CODE = 18
            return
    return


def getFileName(iStreamID, strRawName, bSymTest, iType):
    global ARGS

    strFileName = ""
    if (bSymTest and ARGS.symlinks):
            strFileName = THUMBS_SUBDIR + "/"
    if (iStreamID >= 0):
        strFileName += getStreamFileName(iStreamID, iType)
    else:
        strFileName += getRawFileName(strRawName, iType)
    return strFileName


def prepareEDB():
    global ARGS, EXIT_CODE
    global ESEDB_FILE, ESEDB_TABLE, ESEDB_ICOL_TCI, ESEDB_ICOL_IPD, ESEDB_ICOL_IU

    try:
        from vinetto.lib import pyesedb
    except:
        sys.stderr.write(" Error: Cannot import local library pyesedb\n")
        EXIT_CODE = 19
        return

    pyesedb_ver = pyesedb.get_version()
    sys.stderr.write(" Info: Imported pyesedb version %s\n" % pyesedb_ver)
    help(pyesedb)
    help(pyesedb.file)

    ESEDB_FILE = pyesedb.file()

    ESEDB_FILE.open(ARGS.edbfile)
    ESEDB_TABLE = ESEDB_FILE.get_table_by_name("SystemIndex_0A")

    iColCnt = ESEDB_TABLE.get_number_of_columns()
    for iCol in range(iColCnt):
        column = ESEDB_TABLE.get_column(iCol)
        strColName = column.get_name()
        if (strColName == "System_ThumbnailCacheId"):
            ESEDB_ICOL_TCI = iCol
        if (strColName == "System_ItemPathDisplay"):
            ESEDB_ICOL_IPD = iCol
        if (strColName == "System_ItemUrl"):
            ESEDB_ICOL_IU = iCol
        if (ESEDB_ICOL_TCI != None and ESEDB_ICOL_IPD != None and ESEDB_ICOL_IU != None):
            break

    EXIT_CODE = 19 # TEMP testing pyesedb import


def searchEDB(strTCI):
    global EXIT_CODE
    global ESEDB_FILE, ESEDB_TABLE

    if (ESEDB_ICOL_TCI == None):
        return (None, None)

    iRecCnt = ESEDB_TABLE.get_number_of_records()
    strRecIPD = None
    strRecIU = None
    for iRec in range(iRecCnt):
        record = ESEDB_TABLE.get_record()
        strRecTCI = get_value_data_as_string(ESEDB_ICOL_TCI)
        if (strTCI == strRecTCI):
            if (ESEDB_ICOL_IPD != None):
                strRecIPD = get_value_data_as_string(ESEDB_ICOL_IPD)
            if (ESEDB_ICOL_IU != None):
                strRecIU = get_value_data_as_string(ESEDB_ICOL_IU)
            break
    return (strRecIPD, strRecIU)


def processThumbsTypeOLE(infile, thumbsDB, thumbsDBsize):
    global ARGS, EXIT_CODE
    global IMAGE_TYPE_1_HEADER, IMAGE_TYPE_1_QUANTIZE, IMAGE_TYPE_1_HUFFMAN
    global LAST_BLOCK
    global HTTP_REPORT

    if (thumbsDBsize % 512 ) != 0:
        sys.stderr.write(" Warning: Length of %s == %d not multiple 512\n" % (infile, thumbsDBsize))

    tDB_endian = "<" # Little Endian

    thumbsDB.seek(0x08)
    tDB_GUID             = thumbsDB.read(16)
    tDB_revisionNo       = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    tDB_versionNo        = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    tDB_endianOrder      = thumbsDB.read(2) # 0xFFFE=65534 OR 0xFEFF=65279

    if (tDB_endianOrder == bytearray(b"\xff\xfe")):
        tDB_endian = ">" # Big Endian
    #elif (tDB_endianOrder == bytearray(b"\xfe\xff")):
    #    tDB_endian = "<"

    tDB_sectorSize       = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    tDB_sectorSizeMini   = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    reserved             = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    reserved             = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    reserved             = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_totalSecSAT  = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_firstSecDir  = unpack(tDB_endian+"L", thumbsDB.read(4))[0] # Root directory 1st block
    reserved             = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_streamMinSize    = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_firstSecSSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_totalSecSSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_firstSecMSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_totalSecMSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]

    SATblocks = []
    for i in range(tDB_SID_totalSecSAT):
        iOffset = 0x4c + (i * 4)
        thumbsDB.seek(iOffset)
        SATblocks.append(unpack(tDB_endian+"L", thumbsDB.read(4))[0])

    # -----------------------------------------------------------------------------
    # Analyzing Root Entry directory ...

    i = tDB_SID_firstSecSSAT
    SSATblocks = []
    while (i != LAST_BLOCK):
        SSATblocks.append(i)
        i = nextBlock(thumbsDB, SATblocks, i, tDB_endian)

    currentBlock = tDB_SID_firstSecDir
    iOffset = 0x200 + currentBlock * 0x200
    thumbsDB.seek(iOffset+0x74)
    firstSSATstreamBlock = unpack(tDB_endian+"L", thumbsDB.read(4))[0]

    i = firstSSATstreamBlock
    SSATstreamBlocks = []
    while (i != LAST_BLOCK):
        SSATstreamBlocks.append(i)
        i = nextBlock(thumbsDB, SATblocks, i, tDB_endian)

    iStreamCounter = 0
    while (currentBlock != LAST_BLOCK):
        iOffset = 0x200 + currentBlock * 0x200
        for i in range(iOffset, iOffset + 0x200, 0x80):
            thumbsDB.seek(i)
            pps_nameDir         = thumbsDB.read(0x40)
            pps_nameDirSize     = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
            pps_type            = unpack("B",            thumbsDB.read(1))[0]
            pps_color           = unpack("?",            thumbsDB.read(1))[0]
            pps_PDID            = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            pps_NDID            = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            pps_SDID            = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            pps_CID             = str(hexlify( thumbsDB.read(16) ))[2:-1]
            pps_userflags       = str(hexlify( thumbsDB.read( 4) ))[2:-1]
            pps_tsCreate        = unpack(tDB_endian+"Q", thumbsDB.read(8))[0]
            pps_tsModify        = unpack(tDB_endian+"Q", thumbsDB.read(8))[0]
            pps_SID_firstSecDir = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            pps_SID_sizeDir     = unpack(tDB_endian+"L", thumbsDB.read(4))[0]

            # Convert encoded bytes to unicode string:
            #   a unicode string length is half the bytes length minus 1 (terminal null)
            strRawName = decodeBytes(pps_nameDir)[0:(pps_nameDirSize // 2 - 1)]

            strTSCreate = getFormattedTimeUTC( convertToPyTime(pps_tsCreate) )
            strTSModify = getFormattedTimeUTC( convertToPyTime(pps_tsModify) )

            if (pps_type == 2): # stream files extraction
                if (not ARGS.quiet):
                    print(" Stream Entry\n --------------------")
                    printBlock(strRawName, pps_type, pps_color, pps_PDID, pps_NDID, pps_SDID, pps_CID,
                               pps_userflags, strTSCreate, strTSModify, pps_SID_firstSecDir,
                               pps_SID_sizeDir)

                #strStreamId  = "%04d" % iStreamCounter
                strStreamId = strRawName[::-1] # ...reverse the raw name
                bStreamId = False
                iStreamID = -1
                if (len(strStreamId) < 4):
                    try:
                        iStreamID = int(strStreamId)
                    except ValueError:
                        iStreamID = -1
                if (iStreamID >= 0):
                    #strStreamId = "%04d" % iStreamID
                    bStreamId = True

                setupSymLink(bStreamId)
                if (EXIT_CODE > 0):
                    return

                bytesToWrite = pps_SID_sizeDir
                sr = bytearray(b"")

                if (pps_SID_sizeDir >= 4096): # stream located in the SAT
                    currentStreamBlock = pps_SID_firstSecDir
                    while (currentStreamBlock != LAST_BLOCK):
                        iStreamOffset = 0x200 + currentStreamBlock * 0x200
                        thumbsDB.seek(iStreamOffset)

                        if (bytesToWrite >= 512):
                            sr = sr + thumbsDB.read(512)
                        else:
                            sr = sr + thumbsDB.read(bytesToWrite)
                        bytesToWrite = bytesToWrite - 512
                        currentStreamBlock = nextBlock(thumbsDB, SATblocks, currentStreamBlock, tDB_endian)

                else:                # stream located in the SSAT
                    currentStreamMiniBlock = pps_SID_firstSecDir
                    while (currentStreamMiniBlock != LAST_BLOCK):
                        # Computing offset of the miniBlock to copy
                        # 1 : Which block of the SSATstream?
                        nb = currentStreamMiniBlock // 8
                        # 2 : Where is this block?
                        bl = SSATstreamBlocks[nb]
                        # 3 : Which offset from the start of block?
                        ioffset = (currentStreamMiniBlock % 8) * 64

                        iStreamOffset = 0x200 + bl * 0x200 + ioffset
                        thumbsDB.seek(iStreamOffset)

                        if (bytesToWrite >= 64):
                            sr = sr + thumbsDB.read(64)
                        else:
                            sr = sr + thumbsDB.read(bytesToWrite)
                        bytesToWrite = bytesToWrite - 64
                        # Computing next currentStreamMiniBlock
                        currentStreamMiniBlock = nextBlock(thumbsDB, SSATblocks, currentStreamMiniBlock, tDB_endian)

                # Extraction stream processing ... ---------------------------------

                sr_len = len(sr)

                # Is this a Catalog?
                if (strRawName == "Catalog"):
                    if (not ARGS.quiet):
                        print("       Entries: ---------------------------------------")
                    # -------------------------------------------------------------
                    # Catalog header...

                    iCatOffset      = unpack(tDB_endian+"H", sr[ 0: 2])[0]
                    iCatVersion     = unpack(tDB_endian+"H", sr[ 2: 4])[0]
                    iCatThumbCount  = unpack(tDB_endian+"L", sr[ 4: 8])[0]
                    iCatThumbWidth  = unpack(tDB_endian+"L", sr[ 8:12])[0]
                    iCatThumbHeight = unpack(tDB_endian+"L", sr[12:16])[0]

                    iStreamCounter -= 1

                    # -------------------------------------------------------------
                    # Analyzing Catalog entries ...

                    while (iCatOffset < sr_len):
                        # Preamble...
                        iCatEntryLen       = unpack(tDB_endian+"L", sr[iCatOffset      :iCatOffset +  4])[0]
                        iCatEntryID        = unpack(tDB_endian+"L", sr[iCatOffset +  4 :iCatOffset +  8])[0]
                        iCatEntryTimestamp = unpack(tDB_endian+"Q", sr[iCatOffset +  8 :iCatOffset + 16])[0]
                        # The Catalog Entry Name:
                        # 1. starts after the preamable (16)
                        # 2. end with 4 null bytes (4)
                        # Therefore, the start of the name string is at the end of the preamble
                        #   and the end of the name string is at the end of the entry minus 4
                        iCatEntryName      =                        sr[iCatOffset + 16: iCatOffset + iCatEntryLen - 4]

                        strCatEntryId        = "%d" % (iCatEntryID)
                        strCatEntryTimestamp = getFormattedTimeUTC( convertToPyTime(iCatEntryTimestamp) )
                        strCatEntryName      = decodeBytes(iCatEntryName)
                        if (ARGS.outdir != None and ARGS.symlinks):
                            #os.system( "ln -fs " + ARGS.outdir + THUMBS_SUBDIR + "/" + strCatEntryId + ".jpg " + "\"" +
                            #            ARGS.outdir + strCatEntryName + "\"" )
                            symlink_force(ARGS.outdir + THUMBS_SUBDIR + "/" + strCatEntryId + ".jpg",
                                          ARGS.outdir + strCatEntryName)
                            if (EXIT_CODE > 0):
                                return
                        if (not ARGS.quiet):
                            print("          " + ("% 4s" % strCatEntryId) + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strCatEntryName)
                        addCatalogEntry(iCatEntryID, strCatEntryTimestamp, strCatEntryName)

                        # Next catalog entry...
                        iCatOffset = iCatOffset + iCatEntryLen

                else: # Not a Catalog, an Image entry...
                    # Is EOI at end of stream?
                    if (sr[sr_len - 2: sr_len] != bytearray(b"\xff\xd9")): # ...Not End Of Image (EOI)
                        sys.stderr.write(" Error: Missing End of Image (EOI) marker in stream %d\n" % iStreamCounter)
                        EXIT_CODE = 14
                        return

                    # --------------------------- Header 1 ------------------------
                    # Get file offset
                    headOffset   = unpack(tDB_endian+"L", sr[ 0: 4])[0]
                    headRevision = unpack(tDB_endian+"L", sr[ 4: 8])[0]

                    # Is length OK?
                    if (unpack(tDB_endian+"H", sr[ 8:10])[0] != (sr_len - headOffset)):
                        sys.stderr.write(" Error: Header 1 length mismatch in stream %d\n" % iStreamCounter)
                        EXIT_CODE = 15
                        return

                    if (len(strRawName) >= 4):
                        # ESEDB Search...
                        (strIPD, strIU) = searchEDB(strRawName)
                        if (not ARGS.quiet):
                            print("ESEBD ItemPath: %s" % ("None" if (strIPD == None) else strIPD))
                            print("ESEBD  ItemUrl: %s" % ("None" if (strIU == None) else strIU))
                        if (ARGS.symlinks):
                            if (strIPD != None):
                                symlink_force(ARGS.outdir + THUMBS_SUBDIR + "/" + strRawName + ".jpg",
                                              ARGS.outdir + strIPD)
                            if (strIU != None):
                                fileURL = open(ARGS.outdir + "urls.txt", "a+")
                                fileURL.write(ARGS.outdir + THUMBS_SUBDIR + "/" + strRawName + ".jpg" + " => " + strIU + "\n")
                                fileURL.close()


                    # --------------------------- Header 2 ------------------------
                    # Type 2 Thumbnail Image? (full jpeg)
                    if (sr[headOffset: headOffset + 4] == bytearray(b"\xff\xd8\xff\xe0")):
                        if (ARGS.outdir != None):
                            strFileName = getFileName(iStreamID, strRawName, bStreamId, 2)
                            fileImg = open(ARGS.outdir + strFileName + ".jpg", "wb")
                            fileImg.write(sr[headOffset:])
                            fileImg.close()
                        else: # Not extracting...
                            if (bStreamId):
                                addStreamIdToStreams(iStreamID, 2, "")
                            else:
                                addFileNameToStreams(strRawName, 2, "")

                    # Type 1 Thumbnail Image?
                    elif (unpack(tDB_endian+"L", sr[headOffset: headOffset + 4])[0] == 1):
                        # Is second header OK?
                        if (unpack(tDB_endian+"H", sr[headOffset + 4: headOffset + 6])[0] != (sr_len - headOffset - 0x10)):
                            sys.stderr.write(" Error: Header 2 length mismatch in stream %d\n" % iStreamCounter)
                            EXIT_CODE = 16
                            return

                        if (ARGS.outdir != None and PIL_FOUND):
                            strFileName = getFileName(iStreamID, strRawName, bStreamId, 1)
                            # Type 1 Thumbnail Image processing ...
                            type1sr = ( IMAGE_TYPE_1_HEADER[:0x14] +
                                        IMAGE_TYPE_1_QUANTIZE +
                                        sr[0x1e:0x34] +
                                        IMAGE_TYPE_1_HUFFMAN +
                                        sr[0x34:] )

                            image = Image.open(StringIO.StringIO(type1sr))
                            #r, g, b, a = image.split()
                            #image = Image.merge("RGB", (r, g, b))
                            image = image.transpose(Image.FLIP_TOP_BOTTOM)
                            image.save(ARGS.outdir + strFileName + ".jpg", "JPEG", quality=100)
                        else: # Cannot extract (PIL not found) or not extracting...
                            if (bStreamId):
                                addStreamIdToStreams(iStreamID, 1, "")
                            else:
                                addFileNameToStreams(strRawName, 1, "")
                    else:
                        sys.stderr.write(" Error: Header 2 not found in stream %d\n" % iStreamCounter)
                        EXIT_CODE = 17
                        return

                if (not ARGS.quiet):
                    print(STR_SEP)
                # -----------------------------------------------------------------

            elif (pps_type == 5): # Root Entry
                if (not ARGS.quiet):
                    print(" Root Entry\n --------------------")
                    printBlock(strRawName, pps_type, pps_color, pps_PDID, pps_NDID, pps_SDID, pps_CID,
                               pps_userflags, strTSCreate, strTSModify, pps_SID_firstSecDir,
                               pps_SID_sizeDir)
                if (ARGS.htmlrep):
                    HTTP_REPORT.SetType1(pps_color, pps_PDID, pps_NDID, pps_SDID, pps_CID,
                               pps_userflags, strTSCreate, strTSModify, pps_SID_firstSecDir,
                               pps_SID_sizeDir)
                if (not ARGS.quiet):
                    print(STR_SEP)

            iStreamCounter += 1

        currentBlock = nextBlock(thumbsDB, SATblocks, currentBlock, tDB_endian)

    if isCatalogOutOfSequence():
        sys.stderr.write(" Info: %s - Catalog index number out of usual sequence\n" % infile)

    if isStreamsOutOfSequence():
        sys.stderr.write(" Info: %s - Stream index number out of usual sequence\n" % infile)

    astrStats = extractStats(ARGS.outdir)
    if (not ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (ARGS.htmlrep):
        strSubDir = "."
        if (ARGS.symlinks):
          strSubDir = THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir)

    if (ARGS.outdir != None):
        iCountCatalogEntries = countCatalogEntry()
        if (iCountCatalogEntries > 0):
            if (iCountCatalogEntries != countThumbnails()):
                sys.stderr.write(" Warning: %s - Counts (Catalog != Extracted)\n" % infile)
            else:
                sys.stderr.write(" Info: %s - Counts (Catalog == Extracted)\n" % infile)
        else:
            sys.stderr.write(" Info: %s - No Catalog\n" % infile)


def processThumbsTypeCMMM(infile, thumbsDB, thumbsDBsize):
    global ARGS, TC_FORMAT_TYPE, HTTP_REPORT

    # tDB_endian = "<" ALWAYS

    if (thumbsDBsize < 24):
        print(" Warning: %s too small to process header\n" % infile)
        return

    # Header...
    thumbsDB.seek(0x04)
    tDB_formatVer        = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheType        = unpack("<L", thumbsDB.read(4))[0]
    if (tDB_formatVer > TC_FORMAT_TYPE("Windows 8")):
        thumbsDB.read(4) # Skip an integer size
    tDB_cacheOff1st      = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheOff1stAvail = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheCount       = None # Cache Count not available above Windows 8 v2
    if (tDB_formatVer < TC_FORMAT_TYPE("Windows 8 v3")):
        tDB_cacheCount   = unpack("<L", thumbsDB.read(4))[0]

    strFileType = "CMMM"
    if (not ARGS.quiet):
        print(" Header\n --------------------")
        printDBHead(THUMBS_TYPE_CMMM, strFileType, tDB_formatVer, tDB_cacheType, tDB_cacheOff1st, tDB_cacheOff1stAvail, tDB_cacheCount)
        print(STR_SEP)
    if (ARGS.htmlrep):
        HTTP_REPORT.SetType2(strFileType, tDB_formatVer, tDB_cacheType, tDB_cacheOff1st, tDB_cacheOff1stAvail, tDB_cacheCount)

    # Cache...
    iOffset = tDB_cacheOff1st
    iCacheCounter = 1
    while (True):
        if (thumbsDBsize < (iOffset + 48)):
            print(" Warning: %s too small to process cache entry %d\n" % (infile, iCacheCounter))
            return

        thumbsDB.seek(iOffset)
        tDB_sig      = thumbsDB.read(4)
        tDB_size     = unpack("<L",  thumbsDB.read(4))[0]
        tDB_hash     = unpack("<Q",  thumbsDB.read(8))[0]
        iOffset += 16

        tDB_ext = None # File Extension not available above Windows Vista
        if (tDB_formatVer == TC_FORMAT_TYPE("Windows Vista")):
            tDB_ext = thumbsDB.read(8)
            iOffset += 8

        tDB_idSize   = unpack("<L",  thumbsDB.read(4))[0]
        tDB_padSize  = unpack("<L",  thumbsDB.read(4))[0]
        tDB_dataSize = unpack("<L",  thumbsDB.read(4))[0]
        reserved     = unpack("<L",  thumbsDB.read(4))[0]
        tDB_chksumD  = unpack("<Q",  thumbsDB.read(8))[0]
        tDB_chksumH  = unpack("<Q",  thumbsDB.read(8))[0]
        tDB_id       = thumbsDB.read(tDB_idSize)
        if (tDB_padSize > 0):
            tDB_pad = thumbsDB.read(tDB_padSize)
        tDB_data     = thumbsDB.read(tDB_dataSize)

        iOffset += (32 + tDB_idSize + tDB_padSize + tDB_dataSize)

        # TODO: Check above structure for versions >= Windows 8 and above

        strID  = decodeBytes(tDB_id)
        strExt = None
        if (tDB_ext != None):
            strExt = decodeBytes(tDB_ext)

        # ESEDB Search...
        (strIPD, strIU) = searchEDB(strID)

        if (not ARGS.quiet):
            print(" Cache Entry\n --------------------")
            printDBCache(tDB_sig, tDB_size, tDB_hash, strExt, tDB_idSize, tDB_padSize, tDB_dataSize,
                         tDB_chksumD, tDB_chksumH, strID, strIPD, strIU)

        if (strIPD != None):
            setupSymLink(True)
            if (EXIT_CODE > 0):
                return
            if (ARGS.symlinks):
                if (strIPD != None):
                    symlink_force(ARGS.outdir + THUMBS_SUBDIR + "/" + strID + ".jpg",
                                  ARGS.outdir + strIPD)
                if (strIU != None):
                    fileURL = open(ARGS.outdir + "urls.txt", "a+")
                    fileURL.write(ARGS.outdir + THUMBS_SUBDIR + "/" + strID + ".jpg" + " => " + strIU + "\n")
                    fileURL.close()

        #   Write data to filename...
        if (ARGS.outdir != None):
            strFileName = getFileName(-1, strID, True, 2)
            if (strExt == None):
                # Detect data type ext by magic bytes...
                strFileType = magic.from_buffer(tDB_data, mime=True)
                strExt = strFileType.split("image/", 1)[-1] if ("image/" in strFileType) else "image"
            fileImg = open(ARGS.outdir + strFileName + "." + strExt, "wb")
            fileImg.write(tDB_data)
            fileImg.close()
        else: # Not extracting...
            addFileNameToStreams(strID, 2, "")

        # End of Loop
        iCacheCounter += 1

        if (not ARGS.quiet):
            print(STR_SEP)

        # Check End of File...
        if (thumbsDBsize <= iOffset):
            break

    astrStats = extractStats(ARGS.outdir)
    if (not ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (ARGS.htmlrep):
        strSubDir = "."
        if (ARGS.symlinks):
          strSubDir = THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir)


def processThumbsTypeIMMM(infile, thumbsDB, thumbsDBsize):
    global ARGS, TC_FORMAT_TYPE

    # tDB_endian = "<" ALWAYS

    if (thumbsDBsize < 24):
        print(" Warning: %s too small to process header\n" % infile)
        return

    # Header...
    tDB_formatVer  = unpack("<l", thumbsDB[ 4: 8])[0]
    reserved       = unpack("<l", thumbsDB[ 8:12])[0]
    tDB_entryUsed  = unpack("<l", thumbsDB[12:16])[0]
    tDB_entryCount = unpack("<l", thumbsDB[16:20])[0]
    reserved       = unpack("<l", thumbsDB[20:24])[0]

    strFileType = "IMMM"
    if (not ARGS.quiet):
        print(" Header\n --------------------")
        printDBHead(THUMBS_TYPE_IMMM, strFileType, tDB_formatVer, None, tDB_entryUsed, None, tDB_entryCount)
        print(STR_SEP)
    if (ARGS.htmlrep):
        HTTP_REPORT.SetType3(strFileType, tDB_formatVer, tDB_entryUsed, tDB_entryCount)

    # Cache...
    iOffset = 24
    iEntryCounter = 1
    while (iEntryCounter < tDB_entryCount):
        if (thumbsDBsize < (iOffset + 32)):
            print(" Warning: %s too small to process cache entry %d\n" % (infile, iCacheCounter))
            return

        tDB_hash = unpack("<Q", thumbsDB[iOffset +  0: iOffset + 8])[0]

        iOffFlags = iOffset + 8
        if (tDB_formatVer == TC_FORMAT_TYPE("Windows Vista")):
            tDB_filetime = unpack("<Q", thumbsDB[iOffFlags: iOffFlags + 8])[0]
            iOffFlags += 8

        tDB_flags   = unpack("<l", thumbsDB[iOffFlags +  0: iOffFlags +  4])[0]
        tDB_tc_32   = unpack("<l", thumbsDB[iOffFlags +  4: iOffFlags +  8])[0]
        tDB_tc_96   = unpack("<l", thumbsDB[iOffFlags +  8: iOffFlags + 12])[0]
        tDB_tc_256  = unpack("<l", thumbsDB[iOffFlags + 12: iOffFlags + 16])[0]
        tDB_tc_1024 = unpack("<l", thumbsDB[iOffFlags + 16: iOffFlags + 20])[0]
        tDB_tc_sr   = unpack("<l", thumbsDB[iOffFlags + 20: iOffFlags + 24])[0]

        # TODO: DO MORE!!!

        # End of Loop
        iOffset = iOffFlags + 24
        iEntryCounter += 1

    astrStats = extractStats(ARGS.outdir)
    if (not ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (ARGS.htmlrep):
        strSubDir = "."
        if (ARGS.symlinks):
          strSubDir = THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir)


def processThumbFile(infile, bProcessError=True):
    global ARGS, EXIT_CODE
    global IMAGE_TYPE_1_HEADER, IMAGE_TYPE_1_QUANTIZE, IMAGE_TYPE_1_HUFFMAN
    global HTTP_REPORT


    # Open given Thumbnail file...
    thumbsDBsize = os.stat(infile).st_size
    thumbsDB = open(infile,"rb")

    # Get MD5 of Thumbs.db file...
    thumbsDBmd5 = None
    if (ARGS.md5force) or ((not ARGS.md5never) and (thumbsDBsize < (1024 ** 2) * 512)):
        try:
            # Python >= 2.5
            from hashlib import md5
            thumbsDBmd5 = md5(thumbsDB.read()).hexdigest()
        except:
            # Python < 2.5
            import md5
            thumbsDBmd5 = md5.new(thumbsDB.read()).hexdigest()
        del md5

    # Initialize processing for output...
    if (ARGS.outdir != None):
        # Initializing Type 1 image extraction...
        PIL_FOUND = True
        try:
            from PIL import Image
        except ImportError:
            PIL_FOUND = False
            sys.stderr.write("\n" +
                            " Warning: Cannot find PIL Package Image module.\n" +
                            "          Vinetto will only extract Type 2 thumbnails.\n" +
                            "\n")
        if (PIL_FOUND == True):
            IMAGE_TYPE_1_HEADER   = open(resource_filename("vinetto", "data/header"), "rb").read()
            IMAGE_TYPE_1_QUANTIZE = open(resource_filename("vinetto", "data/quantization"), "rb").read()
            IMAGE_TYPE_1_HUFFMAN  = open(resource_filename("vinetto", "data/huffman"), "rb").read()

    # -----------------------------------------------------------------------------
    # Begin analysis output...

    if (not ARGS.quiet):
        print(STR_SEP)
        print(" File: %s" % infile)
        if (thumbsDBmd5 != None):
            print("  MD5: %s" % thumbsDBmd5)
        print(STR_SEP)

    # -----------------------------------------------------------------------------
    # Analyzing header block...

    sigOLE =      bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") # Standard Sig for OLE2 Thumbs.db file
    sigOLE_Beta = bytearray(b"\x0e\x11\xfc\x0d\xd0\xcf\x11\xe0") # Older Beta Sig for OLE2 Thumbs.db file
    sigCMMM =     bytearray(b"CMMM") # Standard Sig for Thumbcache_*.db files
    sigIMMM =     bytearray(b"IMMM") # Standard Sig for Thumbcache_*.db Index files

    thumbsDB.seek(0)
    thumbsDBdata = thumbsDB.read(0x08)
    if   (thumbsDBdata[0x00:0x08] == sigOLE):
        thumbsDBtype = THUMBS_TYPE_OLE
    elif (thumbsDBdata[0x00:0x08] == sigOLE_Beta):
        thumbsDBtype = THUMBS_TYPE_OLE
    elif (thumbsDBdata[0x00:0x04] == sigCMMM):
        thumbsDBtype = THUMBS_TYPE_CMMM
    elif (thumbsDBdata[0x00:0x04] == sigIMMM):
        thumbsDBtype = THUMBS_TYPE_IMMM
    else:
        if (bProcessError):
            sys.stderr.write(" Error: Header Signature not found in %s\n" % infile)
            EXIT_CODE = 12
        return

    # Initialize optional HTML report...
    if (ARGS.htmlrep):
        HTTP_REPORT = vinetto.vinreport.HttpReport(thumbsDBtype, infile, ARGS.outdir, getEncoding(),
                                (__major__ + "." + __minor__ + "." + __micro__))
        HTTP_REPORT.SetFileSection(thumbsDBsize, thumbsDBmd5)

    if (thumbsDBtype == THUMBS_TYPE_OLE):
        processThumbsTypeOLE(infile, thumbsDB, thumbsDBsize)
    elif (thumbsDBtype == THUMBS_TYPE_CMMM):
        processThumbsTypeCMMM(infile, thumbsDB, thumbsDBsize)
    elif (thumbsDBtype == THUMBS_TYPE_IMMM):
        processThumbsTypeIMMM(infile, thumbsDB, thumbsDBsize)
    else:
        if (bProcessError):
            sys.stderr.write(" Error: No process for Header Signature in %s\n" % infile)
            EXIT_CODE = 12
        return


def processDirectory(thumbDir, filenames=None):
    global ARGS

    # Search for thumbnail cache files:
    #  Thumbs.db, ehthumbs.db, ehthumbs_vista.db, Image.db, Video.db, TVThumb.db, and musicThumbs.db
    #
    #  thumbcache_*.db (2560, 1920, 1600, 1280, 1024, 768, 256, 96, 48, 32, 16, sr, wide, exif, wide_alternate, custom_stream)
    #  iconcache_*.db

    #includes = ['*humbs.db', '*humbs_*.db', 'Image.db', 'Video.db', 'TVThumb.db', 'thumbcache_*.db', 'iconcache_*.db']
    includes = ['*.db']

    if (filenames == None):
        filenames = []
        with os.scandir(thumbDir) as iterFiles:
            for fileEntry in iterFiles:
                if fileEntry.is_file():
                    filenames.append(fileEntry.name)

    # Include files...
    files = []
    for pattern in includes:
        for filename in fnmatch.filter(filenames, pattern):
            files.append(os.path.join(thumbDir, filename))

    # TODO: Check for "Thumbs.db" file and related image files in current directory

    for thumbFile in files:
        processThumbFile(thumbFile, False)


def processRecursiveDirectory():
    global ARGS

    # Walk the directories from given directory recursively down...
    for dirpath, dirnames, filenames in os.walk(ARGS.infile):
        processDirectory(dirpath, filenames)


def processFileSystem():
    global ARGS

    #
    # Process well known Thumbcache DB files with ESE DB enhancement (if available)
    #

    userExtDir = "AppData/Local/Microsoft/Windows/Explorer/"
    userBaseDir = os.path.join(ARGS.infile, "Users/")
    if os.path.isdir(userBaseDir):
        with os.scandir(userBaseDir) as iterDirs:
            for userEntry in iterDirs:
                if not userEntry.is_dir():
                    continue
                userThumbsDir = os.path.join(userEntry.path, userExtDir)
                if not os.path.exists(userThumbsDir): # ...NOT exists?
                    print(" Warning: Skipping %s - does not contain %s\n" % (userEntry.path, userExtDir))
                else:
                    processDirectory(userThumbsDir)
    else:
        sys.stderr.write(" Error: Cannot process from %s as a Windows Vista+ partition\n" % ARGS.infile)
        EXIT_CODE = 10

# ================================================================================
#
# Beginning ...
#
# ================================================================================

def main():
    global ARGS
    ARGS = getArgs()

    if (ARGS.mode == None):
      ARGS.mode = "f"

    # Test Input File parameter...
    if not os.path.exists(ARGS.infile): # ...NOT exists?
        sys.stderr.write(" Error: %s does not exist\n" % ARGS.infile)
        sys.exit(10)
    if (ARGS.mode == "f"): # Traditional Mode...
        if not os.path.isfile(ARGS.infile): # ...NOT a file?
            sys.stderr.write(" Error: %s not a file\n" % ARGS.infile)
            sys.exit(10)
    else: # Directory, Recursive Directory, or Automatic Mode...
        if not os.path.isdir(ARGS.infile): # ...NOT a directory?
            sys.stderr.write(" Error: %s not a directory\n" % ARGS.infile)
            sys.exit(10)
        # Add ending '/' as needed...
        if not ARGS.infile.endswith('/'):
            ARGS.infile += "/"
    if not os.access(ARGS.infile, os.R_OK): # ...NOT readable?
        sys.stderr.write(" Error: %s not readable\n" % ARGS.infile)
        sys.exit(10)

    # Test Output Directory parameter...
    if (ARGS.outdir != None):
        # Testing DIR parameter...
        if not os.path.exists(ARGS.outdir): # ...NOT exists?
            try:
                os.mkdir(ARGS.outdir) # ...make it
                print(" Info: %s was created" % ARGS.outdir)
            except EnvironmentError as e:
                sys.stderr.write(" Error: Cannot create %s\n" % ARGS.outdir)
                sys.exit(11)
        else: # ...exists...
            if not os.path.isdir(ARGS.outdir): # ...NOT a directory?
                sys.stderr.write(" Error: %s is not a directory\n" % ARGS.outdir)
                sys.exit(11)
            elif not os.access(ARGS.outdir, os.W_OK): # ...NOT writable?
                sys.stderr.write(" Error: %s not writable\n" % ARGS.outdir)
                sys.exit(11)
        # Add ending '/' as needed...
        if not ARGS.outdir.endswith('/'):
            ARGS.outdir += "/"

    # Correct MD5 Force parameter...
    if (ARGS.md5force) and (ARGS.md5never):
        ARGS.md5force = False

    # Test EDB file parameter...
    b_EDBOutError = True
    b_EDBFileGood = True
    strErrType = " Error: "
    if (ARGS.mode == "a" and ARGS.edbfile == None):
        ARGS.edbfile = os.path.join(ARGS.infile, "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb")
        b_EDBOutError = False
        strErrType = " Warning: "
    if (ARGS.edbfile != None):
        # Testing EDBFILE parameter...
        if not os.path.exists(ARGS.edbfile): # ...NOT exists?
            sys.stderr.write("%s does not exist\n" % (strErrType + ARGS.edbfile))
            if b_EDBOutError:
                sys.exit(19)
            b_EDBFileGood = False
        elif not os.path.isfile(ARGS.edbfile): # ...NOT a file?
            sys.stderr.write("%s is not a file\n" % (strErrType + ARGS.edbfile))
            if b_EDBOutError:
                sys.exit(19)
            b_EDBFileGood = False
        elif not os.access(ARGS.edbfile, os.R_OK): # ...NOT readable?
            sys.stderr.write("%s not readable\n" % (strErrType + ARGS.edbfile))
            if b_EDBOutError:
                sys.exit(19)
            b_EDBFileGood = False
        if b_EDBFileGood:
            prepareEDB()
        else:
            sys.stderr.write(strErrType + "Skipping any ESE DB file processing on thumbnail files")

    if (EXIT_CODE == 0):
        if (ARGS.mode == "f"): # Traditional Mode
            processThumbFile(ARGS.infile)
        elif (ARGS.mode == "d"): # Directory Mode
            processDirectory(ARGS.infile)
        elif (ARGS.mode == "r"): # Recursive Directory Mode
            processRecursiveDirectory()
        elif (ARGS.mode == "a"): # Automatic Mode - File System
            processFileSystem()
        else: # Unknown Mode
            sys.stderr.write(" Error: Unknown mode (%s) to process " + ARGS.infile + "\n" % ARGS.mode)
            sys.exit(10)

    if (ESEDB_FILE != None):
        ESEDB_FILE.close()

    if (EXIT_CODE > 0):
        sys.exit(EXIT_CODE)
