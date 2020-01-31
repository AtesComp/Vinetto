# -*- coding: UTF-8 -*-
"""
module thumbfile.py
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
file_micro = "3"


import sys
import os
import errno
from io import StringIO
from struct import unpack
from binascii import hexlify, unhexlify

import vinetto.config as config
import vinetto.report as report
import vinetto.esedb as esedb
import vinetto.tdb_catalog as tdb_catalog
import vinetto.tdb_streams as tdb_streams

from vinetto.utils import getFormattedWinToPyTimeUTC, cleanFileName, getEncoding, decodeBytes
from pkg_resources import resource_filename


STR_SEP = " ------------------------------------------------------"
LIST_PLACEHOLDER = ["", ""]

def setSymlink(strTarget, strLink):
    try:
        os.symlink(strTarget, strLink)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(strLink)
            os.symlink(strTarget, strLink)
        else:
            sys.stderr.write(" Error (Symlink): Cannot create symlink %s to file %s\n" % (strLink, strTarget))
            config.EXIT_CODE = 15
            return
    return


def preparePILOutput():
    # Initialize processing for output...
    if (config.ARGS.outdir != None):
        # If already attempted to load PIL...
        if (config.THUMBS_TYPE_OLE_PIL == False):
            return

        # Initializing PIL library for Type 1 image extraction...
        config.THUMBS_TYPE_OLE_PIL = False  # ...attempting to load PIL..
        try:
            from PIL import Image
            config.THUMBS_TYPE_OLE_PIL = True  # ...loaded PIL
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: Imported PIL for possible Type 1 exports\n")
        except ImportError:
            if (not config.ARGS.quiet):
                sys.stderr.write(" Warning: Cannot find PIL Package Image module.\n" +
                                    "          Vinetto will only extract Type 2 thumbnails.\n")
        if (config.THUMBS_TYPE_OLE_PIL == True):
            try:
                config.THUMBS_TYPE_OLE_PIL_TYPE1_HEADER   = open(resource_filename("vinetto", "data/header"), "rb").read()
                config.THUMBS_TYPE_OLE_PIL_TYPE1_QUANTIZE = open(resource_filename("vinetto", "data/quantization"), "rb").read()
                config.THUMBS_TYPE_OLE_PIL_TYPE1_HUFFMAN  = open(resource_filename("vinetto", "data/huffman"), "rb").read()
            except:
                # Hard Error!  The header, quantization, and huffman data files are installed
                #    locally with Vinetto, so missing missing files are bad!
                sys.stderr.write(" Error (Install): Cannot load PIL support data files\n")
                config.EXIT_CODE = 13
                return
    return


def nextOLEBlock(fileTDB, listSAT, iCurrentSector, cEndian):
    # Return next block
    iSATIndex = iCurrentSector // 128  # ...SAT index for search sector
    iSATOffset = iCurrentSector % 128  # ...Sector offset within search sector
    iFileOffset = 512 + listSAT[iSATIndex] * 512 + iSATOffset * 4
    fileTDB.seek(iFileOffset)
    return unpack(cEndian+"L", fileTDB.read(4))[0]


def printOLEHead(strCLSID, iRevisionNo, iVersionNo, cEndian,
                 iSectorSize, iSectorSizeMini, iSAT_TotalSec, iDir1stSec,
                 iStreamSizeMini, iMSAT_1stSec, iMSAT_TotalSec,
                 iDISAT_1stSec, iDISAT_TotalSec):
    print("     Signature: %s" % config.THUMBS_FILE_TYPES[config.THUMBS_TYPE_OLE])
    print("      Class ID: %s" % strCLSID)
    print("      Revision: %d" % iRevisionNo)
    print("       Version: %d" % iVersionNo)
    if (config.ARGS.verbose > 0):
        print("        Endian: %s" % ("Little" if (cEndian == "<") else "Big"))
        print("       DB Info:")
        print("    SAT  Sec Size: %s" % ("None" if iSectorSize == config.OLE_LAST_BLOCK else ("%d" % iSectorSize)))
        print("   MSAT  Sec Size: %s" % ("None" if iSectorSizeMini == config.OLE_LAST_BLOCK else ("%d" % iSectorSizeMini)))
        print("    SAT Total Sec: %s" % ("None" if iSAT_TotalSec == config.OLE_LAST_BLOCK else ("%d" % iSAT_TotalSec)))
        print("    SAT  1st  Sec: %s" % ("None" if iDir1stSec == config.OLE_LAST_BLOCK else ("%d" % iDir1stSec)))
        print("      Stream Size: %s" % ("None" if iStreamSizeMini == config.OLE_LAST_BLOCK else ("%d" % iStreamSizeMini)))
        print("   MSAT  1st  Sec: %s" % ("None" if iMSAT_1stSec == config.OLE_LAST_BLOCK else ("%d" % iMSAT_1stSec)))
        print("   MSAT Total Sec: %s" % ("None" if iMSAT_TotalSec == config.OLE_LAST_BLOCK else ("%d" % iMSAT_TotalSec)))
        print(" DirSAT  1st  Sec: %s" % ("None" if iDISAT_1stSec == config.OLE_LAST_BLOCK else ("%d" % iDISAT_1stSec)))
        print(" DirSAT Total Sec: %s" % ("None" if iDISAT_TotalSec == config.OLE_LAST_BLOCK else ("%d" % iDISAT_TotalSec)))
    return


def printOLECache(strName, dictOLECache):
    print("          Name: %s" % strName)
    print("          Type: %d (%s)" % (dictOLECache["type"], config.OLE_BLOCK_TYPES[dictOLECache["type"]]))
    if (config.ARGS.verbose > 0):
        print("         Color: %d (%s)" % (dictOLECache["color"], "Black" if dictOLECache["color"] else "Red"))
        print("   Prev Dir ID: %s" % ("None" if (dictOLECache["PDID"] == config.OLE_NONE_BLOCK) else str(dictOLECache["PDID"])))
        print("   Next Dir ID: %s" % ("None" if (dictOLECache["NDID"] == config.OLE_NONE_BLOCK) else str(dictOLECache["NDID"])))
        print("   Sub  Dir ID: %s" % ("None" if (dictOLECache["SDID"] == config.OLE_NONE_BLOCK) else str(dictOLECache["SDID"])))
        print("      Class ID: " + dictOLECache["CID"])
        print("    User Flags: " + dictOLECache["userflags"])
        print("        Create: " + getFormattedWinToPyTimeUTC(dictOLECache["create"]))
        print("        Modify: " + getFormattedWinToPyTimeUTC(dictOLECache["modify"]))
        print("       1st Sec: %d" % dictOLECache["SID_firstSecDir"])
        print("          Size: %d" % dictOLECache["SID_sizeDir"])
    return


def processThumbsTypeOLE(infile, fileThumbsDB, iThumbsDBSize):
    preparePILOutput()
    if (config.EXIT_CODE > 0):
        sys.exit(config.EXIT_CODE)

    if (not config.ARGS.quiet):
        if (iThumbsDBSize % 512 ) != 0:
            sys.stderr.write(" Warning: Length of %s == %d not multiple 512\n" % (infile, iThumbsDBSize))

    tDB_endian = "<"  # Little Endian

    # Structure:
    # --------------------
    # The CFBF file consists of a 512-Byte header record followed by a number of
    # sectors whose size is defined in the header. The literature defines Sectors
    # to be either 512 or 4096 bytes in length, although the format is potentially
    # capable of supporting sectors ranging in size from 128-Bytes upwards in
    # powers of 2 (128, 256, 512, 1024, etc.). The lower limit of 128 is the
    # minimum required to fit a single directory entry in a Directory Sector.
    #
    # There are several types of sector that may be present in a CFBF:
    #
    # * Sector Allocation Table (FAT) Sector - contains chains of sector indices
    #     much as a FAT does in the FAT/FAT32 filesystems
    # * MiniSAT Sectors - similar to the SAT but storing chains of mini-sectors
    #     within the Mini-Stream
    # * Double-Indirect SAT (DISAT) Sector - contains chains of SAT sector indices
    # * Directory Sector – contains directory entries
    # * Stream Sector – contains arbitrary file data
    # * Range Lock Sector – contains the byte-range locking area of a large file

    fileThumbsDB.seek(8)  # ...skip magic bytes                              # File Signature: 0xD0CF11E0A1B11AE1 for current version
    tDB_CLSID             = str(hexlify( fileThumbsDB.read(16) ))[2:-1]      # CLSID
    tDB_revisionNo        = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Minor Version
    tDB_versionNo         = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Version

    tDB_endianOrder       = fileThumbsDB.read(2)  # 0xFFFE OR 0xFEFF         # Byte Order, 0xFFFE (Intel)
    if (tDB_endianOrder == bytearray(b"\xff\xfe")):
        tDB_endian = ">"  # Big Endian
    #elif (tDB_endianOrder == bytearray(b"\xfe\xff")):
    #    tDB_endian = "<"

    tDB_SectorSize         = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Sector Shift
    tDB_SectorSizeMini     = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Mini Sector Shift
    reserved               = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # short int reserved
    reserved               = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # int reserved
    reserved               = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count for Directory Chain (4 KB Sectors)
    tDB_SID_SAT_TotalSec   = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count for SAT Chain (512 B Sectors)
    tDB_SID_SAT_FirstSec   = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Root Directory: 1st Sector in Directory Chain
    reserved               = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Signature for transactions (0, not implemented)
    tDB_StreamSize         = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Stream Max Size (typically 4 KB)
    tDB_SID_MSAT_FirstSec  = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # First Sector in the MiniSAT chain
    tDB_SID_MSAT_TotalSec  = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count in the MiniSAT chain
    tDB_SID_DISAT_FirstSec = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # First Sector in the DISAT chain
    tDB_SID_DISAT_TotalSec = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count in the DISAT chain
    iOffset = 76

    if (not config.ARGS.quiet):
        print(" Header\n --------------------")
        printOLEHead(tDB_CLSID, tDB_revisionNo, tDB_versionNo, tDB_endian,
                     tDB_SectorSize, tDB_SectorSizeMini, tDB_SID_SAT_TotalSec, tDB_SID_SAT_FirstSec,
                     tDB_StreamSize, tDB_SID_MSAT_FirstSec, tDB_SID_MSAT_TotalSec,
                     tDB_SID_DISAT_FirstSec, tDB_SID_DISAT_TotalSec)
        print(STR_SEP)

    # Load Sector Allocation Table (SAT) list...
    listSAT = []
    for iCurrentSector in range(tDB_SID_SAT_TotalSec):
        listSAT.append(unpack(tDB_endian+"L", fileThumbsDB.read(4))[0])
        iOffset += 4

    # Load Mini Sector Allocation Table (MiniSAT) list...
    iCurrentSector = tDB_SID_MSAT_FirstSec
    listMiniSAT = []
    while (iCurrentSector != config.OLE_LAST_BLOCK):
        listMiniSAT.append(iCurrentSector)
        iCurrentSector = nextOLEBlock(fileThumbsDB, listSAT, iCurrentSector, tDB_endian)

    # Load Mini SAT Streams list...
    iCurrentSector = tDB_SID_SAT_FirstSec  # First Entry (Root)
    iOffset = 512 + iCurrentSector * 512   # First Entry Offset (to Root)
    fileThumbsDB.seek(iOffset + 116)           # First Entry Offset + First Sec Offset (always Mini @ Root)
    iStream = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # First Mini SAT Entry (usually Mini's Catalog or OLE_LAST_BLOCK)
    listMiniSATStreams = []
    while (iStream != config.OLE_LAST_BLOCK):
        listMiniSATStreams.append(iStream)
        iStream = nextOLEBlock(fileThumbsDB, listSAT, iStream, tDB_endian)

    # =============================================================
    # Process Entries...
    # =============================================================

    tdbStreams = tdb_streams.TDB_Streams()
    tdbCatalog = tdb_catalog.TDB_Catalog()

    iStreamCounter = 1
    while (iCurrentSector != config.OLE_LAST_BLOCK):
        iOffset = 512 + iCurrentSector * 512
        for i in range(iOffset, iOffset + 512, 128):  # 4 Entries per Block: 128 * 4 = 512
            fileThumbsDB.seek(i)
            dictOLECache = {}
            dictOLECache["nameDir"]         = fileThumbsDB.read(64)
            dictOLECache["nameDirSize"]     = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]
            dictOLECache["type"]            = unpack("B",            fileThumbsDB.read(1))[0]
            dictOLECache["color"]           = unpack("?",            fileThumbsDB.read(1))[0]
            dictOLECache["PDID"]            = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]
            dictOLECache["NDID"]            = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]
            dictOLECache["SDID"]            = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]
            dictOLECache["CID"]             = str(hexlify( fileThumbsDB.read(16) ))[2:-1]
            dictOLECache["userflags"]       = str(hexlify( fileThumbsDB.read( 4) ))[2:-1]
            dictOLECache["create"]          = unpack(tDB_endian+"Q", fileThumbsDB.read(8))[0]
            dictOLECache["modify"]          = unpack(tDB_endian+"Q", fileThumbsDB.read(8))[0]
            dictOLECache["SID_firstSecDir"] = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]
            dictOLECache["SID_sizeDir"]     = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]

            # Convert encoded bytes to unicode string:
            #   a unicode string length is half the bytes length minus 1 (terminal null)
            strRawName = decodeBytes(dictOLECache["nameDir"])[0:(dictOLECache["nameDirSize"] // 2 - 1)]

            # Empty Entry processing...
            # =============================================================
            if (dictOLECache["type"] == 0):
                if (not config.ARGS.quiet):
                    print(" Empty Entry %d\n --------------------" % iStreamCounter)
                    printOLECache(strRawName, dictOLECache)
                    print(STR_SEP)

            # Storage Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 1):
                if (not config.ARGS.quiet):
                    print(" Storage Entry %d\n --------------------" % iStreamCounter)
                    printOLECache(strRawName, dictOLECache)
                    print(STR_SEP)

            # Stream Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 2):
                bRegularBlock = (dictOLECache["SID_sizeDir"] >= 4096)

                if (not config.ARGS.quiet):
                    print((" Stream Entry %d (" % iStreamCounter) +
                          ("Standard" if bRegularBlock else "Mini") + ")\n" +
                          " --------------------")
                    printOLECache(strRawName, dictOLECache)

                # Set default Stream Name key to add to Thumb DB Streams (tdbStreams) dict...
                #   Key may be str or int
                keyStreamName = strRawName

                # Check Stream Name for older Thumbs DB name convention...
                strStreamID = strRawName[::-1]  # ...reverse the raw name
                bOldNameID = False  # ...set up older name convention (default is no)
                iStreamID = -1  # ...set up older index name convention...
                if (len(strStreamID) < 4):  # index names are limited to 0 - 999
                    try:
                        iStreamID = int(strStreamID)
                    except ValueError:
                        iStreamID = -1
                if (iStreamID >= 0): # ...valid index name
                    bOldNameID = True  # ...older name convention
                    keyStreamName = iStreamID  # Set older Stream Name key

                # Set entry's first stream sector...
                iCurrentStreamSector = dictOLECache["SID_firstSecDir"]
                # Set entry's read data size...
                iBytesToRead = dictOLECache["SID_sizeDir"]
                # Set entry's read storage...
                bstrStreamData = bytearray(b"")

                # Set entry's regular SAT read support values...
                iReadSize = 512
                listOfNext = listSAT
                if (not bRegularBlock):  # ...stream located in the MiniSAT...
                    # Set entry's MiniSAT read support values...
                    iReadSize = 64
                    listOfNext = listMiniSAT

                # Read data from stream sectors...
                while (iCurrentStreamSector != config.OLE_LAST_BLOCK):
                    # Get stream offset...
                    if (bRegularBlock):  # ...stream located in the SAT...
                            iStreamOffset = 512 + iCurrentStreamSector * 512
                    else:  # ...stream located in the MiniSAT...
                            # Compute offset of the miniBlock to copy...
                            # 1 : Which block of the MiniSAT stream?
                            iIndexMini = iCurrentStreamSector // 8
                            # 2 : Where is this block?
                            iSectorMini = listMiniSATStreams[iIndexMini]
                            # 3 : Which offset from the start of block?
                            iOffsetMini = (iCurrentStreamSector % 8) * iReadSize

                            iStreamOffset = 512 + iSectorMini * 512 + iOffsetMini

                    # Set read location...
                    fileThumbsDB.seek(iStreamOffset)

                    # Read data...
                    if (iBytesToRead >= iReadSize):
                        bstrStreamData = bstrStreamData + fileThumbsDB.read(iReadSize)
                    else:
                        bstrStreamData = bstrStreamData + fileThumbsDB.read(iBytesToRead)
                    iBytesToRead = iBytesToRead - iReadSize

                    # Get entry's next stream sector...
                    iCurrentStreamSector = nextOLEBlock(fileThumbsDB, listOfNext, iCurrentStreamSector, tDB_endian)

                iStreamDataLen = len(bstrStreamData)

                # Catalog Stream processing...
                # -------------------------------------------------------------
                #  Catalogs are related to the older Thumbs DB index name convention
                if (strRawName == "Catalog"):
                    if (not config.ARGS.quiet):
                        print("       Entries: ---------------------------------------")

                    # Get catalog header...
                    iCatOffset      = unpack(tDB_endian+"H", bstrStreamData[ 0: 2])[0]
                    iCatVersion     = unpack(tDB_endian+"H", bstrStreamData[ 2: 4])[0]
                    iCatThumbCount  = unpack(tDB_endian+"L", bstrStreamData[ 4: 8])[0]
                    iCatThumbWidth  = unpack(tDB_endian+"L", bstrStreamData[ 8:12])[0]
                    iCatThumbHeight = unpack(tDB_endian+"L", bstrStreamData[12:16])[0]

                    # Process catalog entries...
                    #  Each catalog entry has an index name, timestamp, and original file name
                    while (iCatOffset < iStreamDataLen):
                        # Preamble...
                        iCatEntryLen       = unpack(tDB_endian+"L", bstrStreamData[iCatOffset      :iCatOffset +  4])[0]
                        iCatEntryID        = unpack(tDB_endian+"L", bstrStreamData[iCatOffset +  4 :iCatOffset +  8])[0]
                        iCatEntryTimestamp = unpack(tDB_endian+"Q", bstrStreamData[iCatOffset +  8 :iCatOffset + 16])[0]
                        # The Catalog Entry Name:
                        # 1. starts after the preamable (16)
                        # 2. end with 4 null bytes (4)
                        # Therefore, the start of the name string is at the end of the preamble
                        #   and the end of the name string is at the end of the entry minus 4
                        bstrCatEntryName   =                        bstrStreamData[iCatOffset + 16: iCatOffset + iCatEntryLen - 4]

                        strCatEntryID        = "%d" % (iCatEntryID)
                        strCatEntryTimestamp = getFormattedWinToPyTimeUTC(iCatEntryTimestamp)
                        strCatEntryName      = decodeBytes(bstrCatEntryName)
                        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                            strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strCatEntryID + ".jpg"
                            setSymlink(strTarget, config.ARGS.outdir + strCatEntryName)
                            if (config.EXIT_CODE > 0):
                                return

                        # Add a "catalog" entry...
                        tdbCatalog[iCatEntryID] = (strCatEntryTimestamp, strCatEntryName)

                        if (not config.ARGS.quiet):
                            print("          " + ("% 4s" % strCatEntryID) + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strCatEntryName)

                        # Next catalog entry...
                        iCatOffset = iCatOffset + iCatEntryLen

                # Image Stream processing...
                # -------------------------------------------------------------
                else:
                    # Is End Of Image (EOI) at end of stream?
                    if (bstrStreamData[iStreamDataLen - 2: iStreamDataLen] != bytearray(b"\xff\xd9")):  # ...Not End Of Image (EOI)
                        sys.stderr.write(" Error (Stream): Missing End of Image (EOI) marker in stream entry %d\n" % iStreamCounter)
                        config.EXIT_CODE = 14
                        return

                    # --- Header 1: Get file offset...
                    headOffset   = unpack(tDB_endian+"L", bstrStreamData[ 0: 4])[0]
                    headRevision = unpack(tDB_endian+"L", bstrStreamData[ 4: 8])[0]

                    # Is length OK?
                    if (unpack(tDB_endian+"H", bstrStreamData[ 8:10])[0] != (iStreamDataLen - headOffset)):
                        sys.stderr.write(" Error (Stream): Header 1 length mismatch in stream entry %d\n" % iStreamCounter)
                        config.EXIT_CODE = 14
                        return

                    strExt = "jpg"
                    if (not bOldNameID):
                        # ESEDB Search...
                        dictESEDB = esedb.searchESEDB(strRawName[strRawName.find("_") + 1: ])  # Raw Name is structured SIZE_THUMBCACHEID
                        if (dictESEDB != None):
                            strFileName = None
                            strCatEntryTimestamp = getFormattedWinToPyTimeUTC(dictESEDB["DATEM"])
                            if (dictESEDB["IURL"] != None):
                                strFileName = dictESEDB["IURL"].split("/")[-1].split("?")[0]
                            if (strFileName != None):
                                if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                                    strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strRawName + "." + strExt
                                    setSymlink(strTarget, config.ARGS.outdir + strFileName)
                                    if (config.EXIT_CODE > 0):
                                        return
                                    fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_URLS, "a+")
                                    fileURL.write(strTarget + " => " + strFileName + "\n")
                                    fileURL.close()

                                # Add a "catalog" entry...
                                tdbCatalog[strRawName] = (strCatEntryTimestamp, strFileName)

                            if (not config.ARGS.quiet):
                                esedb.printESEDBInfo(dictESEDB)
                                if (strFileName != None):
                                    print("  CATALOG " + strRawName + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strFileName)

                    # --- Header 2: Type 2 Thumbnail Image? (Full JPEG)...
                    if (bstrStreamData[headOffset: headOffset + 4] == bytearray(b"\xff\xd8\xff\xe0")):
                        if (config.ARGS.outdir != None):
                            strFileName = tdbStreams.getFileName(keyStreamName, strExt)
                            fileImg = open(config.ARGS.outdir + strFileName, "wb")
                            fileImg.write(bstrStreamData[headOffset:])
                            fileImg.close()
                        else:  # Not extracting...
                            tdbStreams[keyStreamName] = LIST_PLACEHOLDER

                    # --- Header 2: Type 1 Thumbnail Image? (Partial JPEG)...
                    elif (unpack(tDB_endian+"L", bstrStreamData[headOffset: headOffset + 4])[0] == 1):
                        # Is second header OK?
                        if (unpack(tDB_endian+"H", bstrStreamData[headOffset + 4: headOffset + 6])[0] != (iStreamDataLen - headOffset - 16)):
                            sys.stderr.write(" Error (Stream): Header 2 length mismatch in stream entry %d\n" % iStreamCounter)
                            config.EXIT_CODE = 14
                            return

                        if (config.ARGS.outdir != None and config.THUMBS_TYPE_OLE_PIL):
                            strFileName = tdbStreams.getFileName(keyStreamName, strExt)

                            # Construct thumbnail image from standard blocks and stored image data...
                            bstrImage = ( config.THUMBS_TYPE_OLE_PIL_TYPE1_HEADER[:20] +
                                          config.THUMBS_TYPE_OLE_PIL_TYPE1_QUANTIZE + bstrStreamData[30:52] +
                                          config.THUMBS_TYPE_OLE_PIL_TYPE1_HUFFMAN  + bstrStreamData[52:] )

                            image = Image.open(StringIO.StringIO(bstrImage))
                            #r, g, b, a = image.split()
                            #image = Image.merge("RGB", (r, g, b))
                            image = image.transpose(Image.FLIP_TOP_BOTTOM)
                            image.save(config.ARGS.outdir + strFileName, "JPEG", quality=100)
                        else:  # Cannot extract (PIL not found) or not extracting...
                            tdbStreams[keyStreamName] = LIST_PLACEHOLDER
                    else:
                        sys.stderr.write(" Error (Stream): Header 2 not found in stream entry %d\n" % iStreamCounter)
                        config.EXIT_CODE = 14
                        return

                if (not config.ARGS.quiet):
                    print(STR_SEP)

            # Lock Bytes Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 3):
                if (not config.ARGS.quiet):
                    print(" Lock Bytes Entry %d\n --------------------" % iStreamCounter)
                    printOLECache(strRawName, dictOLECache)
                    print(STR_SEP)

            # Property Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 4):
                if (not config.ARGS.quiet):
                    print(" Property Entry %d\n --------------------" % iStreamCounter)
                    printOLECache(strRawName, dictOLECache)
                    print(STR_SEP)

            # Root Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 5):  # ...ROOT should always be first entry
                if (not config.ARGS.quiet):
                    print(" Root Entry %d\n --------------------" % iStreamCounter)
                    printOLECache(strRawName, dictOLECache)
                    print(STR_SEP)

                if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
                    # Set the OLE Head for the HTTP report using the Root Entry info...
                    config.HTTP_REPORT.setOLE(dictOLECache)

            iStreamCounter += 1

        iCurrentSector = nextOLEBlock(fileThumbsDB, listSAT, iCurrentSector, tDB_endian)

    # Process end of file...
    # -----------------------------------------------------------------
    if (config.ARGS.verbose > 0):
        if (tdbCatalog.isOutOfSequence()):
            sys.stderr.write(" Info: %s - Catalog index number out of usual sequence\n" % infile)

    if (config.ARGS.verbose > 0):
        if (tdbStreams.isOutOfSequence()):
            sys.stderr.write(" Info: %s - Stream index number out of usual sequence\n" % infile)

    astrStats = tdbStreams.extractStats()

    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")

    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        config.HTTP_REPORT.flush(astrStats, strSubDir, tdbStreams, tdbCatalog)
        if (config.EXIT_CODE > 0):
            return

    if (not config.ARGS.quiet):
        if (len(tdbCatalog) > 0):
            if (tdbCatalog.getCount() != tdbStreams.getCount()):
                sys.stderr.write(" Warning: %s - Counts (Catalog != Extracted)\n" % infile)
            else:
                if (config.ARGS.verbose > 0):
                    sys.stderr.write(" Info: %s - Counts (Catalog == Extracted)\n" % infile)
        else:
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: %s - No Catalog\n" % infile)


def printCMMMHead(dictCMMMMeta):
    print("     Signature: %s" % config.THUMBS_FILE_TYPES[config.THUMBS_TYPE_CMMM])
    print("        Format: %d (%s)" % (dictCMMMMeta["FormatType"], dictCMMMMeta["FormatTypeStr"]))
    print("          Type: %d (%s)" % (dictCMMMMeta["CacheType"], dictCMMMMeta["CacheTypeStr"]))
    if (config.ARGS.verbose > 0):
        print("    Cache Info:")
        print("          Offset: %s" % ("None" if (dictCMMMMeta["CacheOff1st"] == None) else ("%d" % dictCMMMMeta["CacheOff1st"])))
        print("   1st Available: %s" % ("None" if (dictCMMMMeta["CacheOff1stAvail"] == None) else ("%d" % dictCMMMMeta["CacheOff1stAvail"])))
        print("           Count: %s" % ("None" if (dictCMMMMeta["CacheCount"] == None) else ("%d" % dictCMMMMeta["CacheCount"])))
    return


def printCMMMCache(strSig, iSize, strHash, strExt, iIdSize, iPadSize, iDataSize, iWidth, iHeight, iChkSumD, iChkSumH, keyStreamName, dictESEDB):
    print("     Signature: %s" % strSig)
    if (config.ARGS.verbose > 0):
        print("          Size: %d" % iSize)
        print("          Hash: %s" % strHash)
        print("     Extension: %s" % strExt)
        print("       ID Size: %d" % iIdSize)
        print("      Pad Size: %d" % iPadSize)
        print("     Data Size: %d" % iDataSize)
        print("  Image  Width: %d" % iWidth)
        print("  Image Height: %d" % iHeight)
        print(" Data Checksum: %d" % iChkSumD)
        print(" Head Checksum: %d" % iChkSumH)
    print("            ID: %s" % keyStreamName)
    if (dictESEDB != None):
        esedb.printESEDBInfo(dictESEDB)
    return


def processThumbsTypeCMMM(infile, fileThumbsDB, iThumbsDBSize):
    # tDB_endian = "<" ALWAYS Little???

    if (iThumbsDBSize < 24):
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: %s too small to process header\n" % infile)
        return

    # Header...
    dictCMMMMeta = {}
    fileThumbsDB.seek(4)

    dictCMMMMeta["FormatType"]       = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["FormatTypeStr"]    = "Unknown Format"
    try:
        dictCMMMMeta["FormatTypeStr"] = list(config.TC_FORMAT_TYPE.keys())[list(config.TC_FORMAT_TYPE.values()).index(dictCMMMMeta["FormatType"])]
    except:
        pass

    dictCMMMMeta["CacheType"]        = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["CacheTypeStr"] = "Unknown Type"
    try:
        dictCMMMMeta["CacheTypeStr"] = ("thumbcache_" +
                        config.TC_CACHE_TYPE[config.TC_FORMAT_TO_CACHE[dictCMMMMeta["FormatType"]]][dictCMMMMeta["CacheType"]] +
                        ".db")
    except:
        pass

    if (dictCMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8")):
        reserved = fileThumbsDB.read(4)  # Skip an integer size

    dictCMMMMeta["CacheOff1st"]      = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["CacheOff1stAvail"] = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["CacheCount"]       = None  # Cache Count not available above Windows 8 v2
    if (dictCMMMMeta["FormatType"] < config.TC_FORMAT_TYPE.get("Windows 8 v3")):
        dictCMMMMeta["CacheCount"]   = unpack("<L", fileThumbsDB.read(4))[0]


    if (not config.ARGS.quiet):
        print(" Header\n --------------------")
        printCMMMHead(dictCMMMMeta)
        print(STR_SEP)

    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        config.HTTP_REPORT.setCMMM(dictCMMMMeta)

    # =============================================================
    # Process Cache Entries...
    # =============================================================

    tdbStreams = tdb_streams.TDB_Streams()
    tdbCatalog = tdb_catalog.TDB_Catalog()

    iOffset = dictCMMMMeta["CacheOff1st"]
    iCacheCounter = 1
    while (True):
        if (iThumbsDBSize < (iOffset + 48)):
            if (not config.ARGS.quiet):
                sys.stderr.write(" Warning: Remaining cache entry %d too small to process\n" % iCacheCounter)
            break

        fileThumbsDB.seek(iOffset)
        tDB_sig = fileThumbsDB.read(4)
        if (tDB_sig != config.THUMBS_SIG_CMMM):
            break
        tDB_size = unpack("<L", fileThumbsDB.read(4))[0]
        tDB_hash = unpack("<Q", fileThumbsDB.read(8))[0]
        iOffset += 16

        tDB_ext = None  # File Extension not available above Windows Vista
        if (dictCMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows Vista")):
            tDB_ext = fileThumbsDB.read(8)  # 2 bytes * 4 wchar_t characters
            iOffset += 8

        tDB_idSize   = unpack("<L",  fileThumbsDB.read(4))[0]
        tDB_padSize  = unpack("<L",  fileThumbsDB.read(4))[0]
        tDB_dataSize = unpack("<L",  fileThumbsDB.read(4))[0]
        iOffset += 12

        tDB_width  = None  # Image Width  not available below Windows 8
        tDB_height = None  # Image Height not available below Windows 8
        if (dictCMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            tDB_width  = unpack("<L",  fileThumbsDB.read(4))[0]
            tDB_height = unpack("<L",  fileThumbsDB.read(4))[0]
            iOffset += 8

        reserved     = unpack("<L",  fileThumbsDB.read(4))[0]
        tDB_chksumD  = unpack("<Q",  fileThumbsDB.read(8))[0]
        tDB_chksumH  = unpack("<Q",  fileThumbsDB.read(8))[0]
        iOffset += 20

        tDB_id = None
        if (tDB_idSize > 0):
            tDB_id   = fileThumbsDB.read(tDB_idSize)
        tDB_pad = None
        if (tDB_padSize > 0):
            tDB_pad  = fileThumbsDB.read(tDB_padSize)
        tDB_data = None
        if (tDB_dataSize > 0):
            tDB_data = fileThumbsDB.read(tDB_dataSize)

        iOffset += (tDB_idSize + tDB_padSize + tDB_dataSize)

        # Set default Stream Name key to add to Thumb DB Streams (tdbStreams) dict...
        #   Key may be str or int
        keyStreamName = None
        if (tDB_id != None):
            keyStreamName = decodeBytes(tDB_id)
        else:
            continue  # ...no ID, so probably empty last entry

        strHash = format(tDB_hash, 'x')

        strExt = None
        # Try the given Vista ext...
        if (tDB_ext != None):
            strExt = decodeBytes(tDB_ext)
        if (tDB_dataSize > 0):
            # Detect data type ext by magic bytes...
            tupleImageTypes = (
                    ( bytearray(b'\x42\x4D'), "bmp" ),                         # BM
                    ( bytearray(b'\xFF\xD8\xFF\xE0'), "jpg" ),                 # ....
                    ( bytearray(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'), "png" )  # .PNG\n\r\sub\r
                )
            for tupleImageType in tupleImageTypes:
                if (tupleImageType[0] == tDB_data[0:len(tupleImageType[0])]):
                    strExt = tupleImageType[1]

            # If there still is no ext, use a neutral default ".img"...
            if (strExt == None):
                strExt = "img"
        # Otherwise,
        #    No Data, no Ext!

        # ESEDB Search...
        dictESEDB = esedb.searchESEDB(keyStreamName)

        if (not config.ARGS.quiet):
            print(" Cache Entry %d\n --------------------" % iCacheCounter)
            printCMMMCache(tDB_sig.decode(), tDB_size, strHash, strExt, tDB_idSize, tDB_padSize, tDB_dataSize,
                         tDB_width, tDB_height, tDB_chksumD, tDB_chksumH, keyStreamName, dictESEDB)

        strCleanFileName = cleanFileName(keyStreamName)

        if (tDB_dataSize > 0):
            # Setup symbolic link to filename...
            if (dictESEDB != None):
                strFileName = None
                strCatEntryTimestamp = getFormattedWinToPyTimeUTC(dictESEDB["DATEM"])
                if (dictESEDB["IURL"] != None):
                    strFileName = dictESEDB["IURL"].split("/")[-1].split("?")[0]
                if (strFileName != None):
                    if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                        strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strCleanFileName + "." + strExt
                        setSymlink(strTarget, config.ARGS.outdir + strFileName)
                        if (config.EXIT_CODE > 0):
                                return
                        fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_URLS, "a+")
                        fileURL.write(strTarget + " => " + strFileName + "\n")
                        fileURL.close()

                    # Add a "catalog" entry...
                    tdbCatalog[strCleanFileName] = (strCatEntryTimestamp, strFileName)

                    if (not config.ARGS.quiet):
                        print("  CATALOG " + strRawName + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strFileName)

            # Write data to filename...
            if (config.ARGS.outdir != None):
                strFileName = tdbStreams.getFileName(strCleanFileName, strExt)
                fileImg = open(config.ARGS.outdir + strFileName, "wb")
                fileImg.write(tDB_data)
                fileImg.close()
            else:  # Not extracting...
                tdbStreams[strCleanFileName] = LIST_PLACEHOLDER

        # End of Loop
        iCacheCounter += 1

        if (not config.ARGS.quiet):
            print(STR_SEP)

        # Check End of File...
        if (iThumbsDBSize <= iOffset):
            break

    astrStats = tdbStreams.extractStats()
    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        config.HTTP_REPORT.flush(astrStats, strSubDir, tdbStreams, tdbCatalog)
        if (config.EXIT_CODE > 0):
            return


def printIMMMHead(dictIMMMMeta, iFileSize):
    print("     Signature: %s" % config.THUMBS_FILE_TYPES[config.THUMBS_TYPE_IMMM])
    print("        Format: %d (%s)" % (dictIMMMMeta["FormatType"], dictIMMMMeta["FormatTypeStr"]))
    print("          Size: %d" % iFileSize)
    print("    Entry Info:")
    print("        Reserved: %s" % ("None" if (dictIMMMMeta["Reserved01"] == None) else ("%d" % dictIMMMMeta["Reserved01"])))
    print("            Used: %s" % ("None" if (dictIMMMMeta["EntryUsed"] == None) else ("%d" % dictIMMMMeta["EntryUsed"])))
    print("           Count: %s" % ("None" if (dictIMMMMeta["EntryCount"] == None) else ("%d" % dictIMMMMeta["EntryCount"])))
    print("           Total: %s" % ("None" if (dictIMMMMeta["EntryTotal"] == None) else ("%d" % dictIMMMMeta["EntryTotal"])))
    return


def printIMMMCache(strHash, iFileTime, strFlags,
                   iOffset_16, iOffset_32, iOffset_48, iOffset_96, iOffset_256, iOffset_1024,
                   iOffset_1280, iOffset_1600, iOffset_1920, iOffset_2560,
                   iOffset_sr, iOffset_wide, iOffset_exif, iOffset_wide_alternate,
                   iOffset_custom_stream):
    iNegOne = config.OLE_NONE_BLOCK  # ...filter out unused values
    if (config.ARGS.verbose > 1):
        iNegOne = None  # ...show unused, i.e., remove filter (set to same as first filter)
    if (strHash != None):
        print("          Hash: %s" % strHash)
    if (iFileTime != None):
        print("        Modify: %s" % getFormattedWinToPyTimeUTC(iFileTime))
    if (strFlags != None):
        print("         Flags: %s" % strFlags)
    if (config.ARGS.verbose > 0):
        if (iOffset_16 != None and iOffset_16 != iNegOne):
            print("   Offset   16: %d" % iOffset_16)
        if (iOffset_32 != None and iOffset_32 != iNegOne):
            print("   Offset   32: %d" % iOffset_32)
        if (iOffset_48 != None and iOffset_48 != iNegOne):
            print("   Offset   48: %d" % iOffset_48)
        if (iOffset_96 != None and iOffset_96 != iNegOne):
            print("   Offset   96: %d" % iOffset_96)
        if (iOffset_256 != None and iOffset_256 != iNegOne):
            print("   Offset  256: %d" % iOffset_256)
        if (iOffset_1024 != None and iOffset_1024 != iNegOne):
            print("   Offset 1024: %d" % iOffset_1024)
        if (iOffset_1280 != None and iOffset_1280 != iNegOne):
            print("   Offset 1280: %d" % iOffset_1280)
        if (iOffset_1600 != None and iOffset_1600 != iNegOne):
            print("   Offset 1600: %d" % iOffset_1600)
        if (iOffset_1920 != None and iOffset_1920 != iNegOne):
            print("   Offset 1920: %d" % iOffset_1920)
        if (iOffset_2560 != None and iOffset_2560 != iNegOne):
            print("   Offset 2560: %d" % iOffset_2560)
        if (iOffset_sr != None and iOffset_sr != iNegOne):
            print("   Offset   sr: %d" % iOffset_sr)
        if (iOffset_wide != None and iOffset_wide != iNegOne):
            print("   Offset wide: %d" % iOffset_wide)
        if (iOffset_exif != None and iOffset_exif != iNegOne):
            print("   Offset exif: %d" % iOffset_exif)
        if (iOffset_wide_alternate != None and iOffset_wide_alternate != iNegOne):
            print("   Offset walt: %d" % iOffset_wide_alternate)
        if (iOffset_custom_stream != None and iOffset_custom_stream != iNegOne):
            print("   Offset cust: %d" % iOffset_custom_stream)
    return


def processThumbsTypeIMMM(infile, fileThumbsDB, iThumbsDBSize, iInitialOffset = 0):
    # tDB_endian = "<" ALWAYS

    if (iThumbsDBSize < 24):
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: %s too small to process header\n" % infile)
        return

    # Setup inital offset...
    iOffset = iInitialOffset + 4

    # Header...
    dictIMMMMeta = {}
    fileThumbsDB.seek(iOffset)

    dictIMMMMeta["FormatType"]       = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["FormatTypeStr"]    = "Unknown Format"
    try:
        dictIMMMMeta["FormatTypeStr"] = list(config.TC_FORMAT_TYPE.keys())[list(config.TC_FORMAT_TYPE.values()).index(dictIMMMMeta["FormatType"])]
    except:
        pass

    dictIMMMMeta["Reserved01"]    = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["EntryUsed"]  = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["EntryCount"] = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["EntryTotal"] = unpack("<L", fileThumbsDB.read(4))[0]
    iOffset += 20

    iBlockSize = 24
    if (dictIMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows 10")):
        dictIMMMMeta["Reserved02"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved03"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved04"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved05"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved06"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved07"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved08"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved09"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved10"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved11"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved12"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved13"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved14"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved15"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved16"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved17"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved18"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved19"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved20"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved21"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved22"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved23"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved24"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved25"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved26"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved27"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved28"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved29"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Reserved30"] = unpack("<L", fileThumbsDB.read(4))[0]
        iOffset += 116

    if (not config.ARGS.quiet):
        print(" Header\n --------------------")
        printIMMMHead(dictIMMMMeta, iThumbsDBSize)
        print(STR_SEP)

    if (config.ARGS.htmlrep):
        config.HTTP_REPORT.setIMMM(dictIMMMMeta)

    # =============================================================
    # Process Cache Entries...
    # =============================================================

    tdbStreams = tdb_streams.TDB_Streams()
    #tdbCatalog = tdb_catalog.TDB_Catalog()

    iCacheCounter = 1
    iPrinted = 0
    while (True):
        if (iThumbsDBSize < (iOffset + 32)):
            if (not config.ARGS.quiet):
                sys.stderr.write(" Warning: %s too small to process cache entry %d\n" % (infile, iCacheCounter))
            return

        iOffEntry = 0
        fileThumbsDB.seek(iOffset)

        tDB_hash = unpack("<Q", fileThumbsDB.read(8))[0]
        iOffEntry += 8

        tDB_filetime = None
        if (dictIMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows Vista")):
            tDB_filetime = unpack("<Q", fileThumbsDB.read(8))[0]
            iOffEntry += 8

        tDB_flags = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        tDB_tc_16 = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            tDB_tc_16 = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_32   = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        tDB_tc_48 = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            tDB_tc_48 = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_96   = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        tDB_tc_256  = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        tDB_tc_768 = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            tDB_tc_768 = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_1024 = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        tDB_tc_1280 = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            tDB_tc_1280 = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_1600 = None
        if (dictIMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows 8.1")):
            tDB_tc_1600 = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_1920 = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            tDB_tc_1920 = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_2560 = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            tDB_tc_2560 = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_sr   = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        tDB_tc_wide = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            tDB_tc_wide = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_exif = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            tDB_tc_exif = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_wide_alternate = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8 v3")):
            tDB_tc_wide_alternate = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        tDB_tc_custom_stream = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            tDB_tc_custom_stream = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        strHash = format(tDB_hash, '016x')
        strFlags = format(tDB_flags, "032b")[2:] # bin(tDB_flags)[2:]

        if (not config.ARGS.quiet):
            bPrint = 2  # full print (default)
            if (config.ARGS.verbose > 2):
                pass  # full print
            elif (config.ARGS.verbose > 1):
                if (tDB_hash == 0x0 and tDB_flags == 0x0):  # ...totally empty...
                    bPrint = 1  # ...short print
            elif (config.ARGS.verbose > 0):
                if (tDB_flags == 0x0 or tDB_flags == 0xffffffff):  # ...empty or unused...
                    bPrint = 1  # ...short print
                if (tDB_hash == 0x0 and tDB_flags == 0x0):  # ...totally empty...
                    bPrint = 0  # ...don't print
            else: # Standard Print
                if (tDB_flags == 0x0 or tDB_flags == 0xffffffff):  # ...empty or unused...
                    bPrint = 0  # ...don't print
            if (bPrint):
                print(" Cache Entry %d\n --------------------" % iCacheCounter)
                if (bPrint == 1):
                    print("   Empty!")
                else:  # bPrint > 1
                    printIMMMCache(strHash, tDB_filetime, strFlags,
                                   tDB_tc_16, tDB_tc_32, tDB_tc_48, tDB_tc_96, tDB_tc_256, tDB_tc_1024,
                                   tDB_tc_1280, tDB_tc_1600, tDB_tc_1920, tDB_tc_2560,
                                   tDB_tc_sr, tDB_tc_wide, tDB_tc_exif, tDB_tc_wide_alternate,
                                   tDB_tc_custom_stream)
                print(STR_SEP)
                iPrinted += 1

        # TODO: DO MORE!!!

        # End of Loop
        iCacheCounter += 1

        # Check End of File...
        iOffset += iOffEntry
        #if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
        #    if (iOffEntry < 72):
        #        iOffset += (72 - iOffEntry)
        if (iThumbsDBSize <= iOffset):
            break

#    # TEST Print stats on process...
#    print("  Printed: %d,  Offset: %d,  Diff %d" % (iPrinted, iOffset, iThumbsDBSize - iOffset))

    astrStats = tdbStreams.extractStats()
    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        config.HTTP_REPORT.flush(astrStats, strSubDir)
        if (config.EXIT_CODE > 0):
            return


def processThumbFile(infile):
    # Open given Thumbnail file...
    try:
        fileThumbsDB = open(infile, "rb")
    except:
        if (config.ARGS.mode == "f"):  # ...only processing a single file, error
            sys.stderr.write(" Error (ThumbDB): Cannot open file %s\n" % infile)
            config.EXIT_CODE = 12
        elif (not config.ARGS.quiet):  # ...for modes "d", "r", and "a", continue
            sys.stderr.write(" Warning: Cannot open file %s\n" % infile)
        return

    # Setup file Header information...
    dictHead = {}
    dictHead["FilePath"] = infile
    dictHead["FileSize"] = None
    dictHead["MD5"] = None
    dictHead["FileType"] = None

    # Get file size of file...
    try:
        dictHead["FileSize"] = os.stat(infile).st_size
    except:
        if (config.ARGS.mode == "f"):  # ...only processing a single file, error
            sys.stderr.write(" Error (ThumbDB): Cannot get size of file %s\n" % infile)
            config.EXIT_CODE = 12
        elif (not config.ARGS.quiet):  # ...for modes "d", "r", and "a", continue
            sys.stderr.write(" Warning: Cannot get size of file %s\n" % infile)
        return

    # Get MD5 of file...
    if (config.ARGS.md5force) or ((not config.ARGS.md5never) and (dictHead["FileSize"] < (1024 ** 2) * 512)):
        try:
            # Python >= 2.5
            from hashlib import md5
            dictHead["MD5"] = md5(fileThumbsDB.read()).hexdigest()
        except:
            # Python < 2.5
            import md5
            dictHead["MD5"] = md5.new(fileThumbsDB.read()).hexdigest()
        del md5

    # -----------------------------------------------------------------------------
    # Begin analysis output...

    if (not config.ARGS.quiet):
        print(STR_SEP)
        print(" File: %s" % dictHead["FilePath"])
        if (dictHead["MD5"] != None):
            print("  MD5: %s" % dictHead["MD5"])
        print(STR_SEP)

    # -----------------------------------------------------------------------------
    # Analyzing header block...

    iInitialOffset = 0
    fileThumbsDB.seek(0)
    bstrSig = fileThumbsDB.read(8)
    if   (bstrSig[0:8] == config.THUMBS_SIG_OLE):
        dictHead["FileType"] = config.THUMBS_TYPE_OLE
    elif (bstrSig[0:8] == config.THUMBS_SIG_OLEB):
        dictHead["FileType"] = config.THUMBS_TYPE_OLE
    elif (bstrSig[0:4] == config.THUMBS_SIG_CMMM):
        dictHead["FileType"] = config.THUMBS_TYPE_CMMM
    elif (bstrSig[0:4] == config.THUMBS_SIG_IMMM):
        dictHead["FileType"] = config.THUMBS_TYPE_IMMM
    elif (bstrSig[0:8] == bytearray(b"\x0c\x000 ") + config.THUMBS_SIG_IMMM):
        dictHead["FileType"] = config.THUMBS_TYPE_IMMM
        iInitialOffset = 4
    else:  # ...Header Signature not found...
        if (config.ARGS.mode == "f"):
            sys.stderr.write(" Error (ThumbDB): Header Signature not found in %s\n" % dictHead["FilePath"])
            config.EXIT_CODE = 12
        elif (not config.ARGS.quiet):
            sys.stderr.write(" Warning: Header Signature not found in %s\n" % dictHead["FilePath"])
        return  # ..always return

    # Initialize optional HTML report...
    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        config.HTTP_REPORT = report.HtmlReport(getEncoding(), config.ARGS.outdir, dictHead)

    if (dictHead["FileType"] == config.THUMBS_TYPE_OLE):
        processThumbsTypeOLE(dictHead["FilePath"], fileThumbsDB, dictHead["FileSize"])
    elif (dictHead["FileType"] == config.THUMBS_TYPE_CMMM):
        processThumbsTypeCMMM(dictHead["FilePath"], fileThumbsDB, dictHead["FileSize"])
    elif (dictHead["FileType"] == config.THUMBS_TYPE_IMMM):
        processThumbsTypeIMMM(dictHead["FilePath"], fileThumbsDB, dictHead["FileSize"], iInitialOffset)
    else:  # ...should never hit this as dictHead["FileType"] is set in prior "if" block above,
           # ...dictHead["FileType"] should always be set properly
        if (config.ARGS.mode == "f"):
            sys.stderr.write(" Error (ThumbDB): No process for Header Signature in %s\n" % dictHead["FilePath"])
            config.EXIT_CODE = 12
        elif (not config.ARGS.quiet):
            sys.stderr.write(" Warning: No process for Header Signature in %s\n" % dictHead["FilePath"])

    return


