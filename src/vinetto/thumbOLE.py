# -*- coding: UTF-8 -*-
"""
module thumbOLE.py
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumb Database files
 Copyright (C) 2005, 2006 by Michel Roukine
 Copyright (C) 2019-2025 by Keven L. Ates

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
file_micro = "12"


import sys
import os
import errno
from io import BytesIO
from struct import unpack
from binascii import hexlify
from numpy import character, intc
from pkg_resources import resource_filename

import vinetto.config as config
import vinetto.esedb as esedb
import vinetto.tdb_catalog as tdb_catalog
import vinetto.tdb_streams as tdb_streams
import vinetto.utils as utils
import vinetto.error as verror


def preparePILOutput():
    # Initialize processing for output...
    if (config.ARGS.outdir != None):
        # If already attempted to load PIL...
        if (config.THUMBS_TYPE_OLE_PIL == False):
            return

        # Initializing PIL library for Type 1 image extraction...
        config.THUMBS_TYPE_OLE_PIL = False  # ...attempting to load PIL..
        try:
            from PIL import Image, ImageChops
            config.THUMBS_TYPE_OLE_PIL = True  # ...loaded PIL
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: Imported PIL for possible Type 1 exports\n")
        except ImportError:
            if (config.ARGS.verbose >= 0):
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
                raise verror.InstallError(" Error: Cannot load PIL support data files!")
    return


def nextBlock(fileTDB, listSAT, iCurrentSector, cEndian):
    # Return next block
    iSATIndex = iCurrentSector // 128  # ...SAT index for search sector
    iSATOffset = iCurrentSector % 128  # ...Sector offset within search sector
    iFileOffset = 512 + listSAT[iSATIndex] * 512 + iSATOffset * 4
    fileTDB.seek(iFileOffset)
    return unpack(cEndian+"L", fileTDB.read(4))[0]


def printHead(strCLSID, iRevisionNo, iVersionNo, cEndian,
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
        if iSectorSize     == config.OLE_LAST_BLOCK: iSectorSize     = None
        if iSectorSizeMini == config.OLE_LAST_BLOCK: iSectorSizeMini = None
        if iSAT_TotalSec   == config.OLE_LAST_BLOCK: iSAT_TotalSec   = None
        if iDir1stSec      == config.OLE_LAST_BLOCK: iDir1stSec      = None
        if iStreamSizeMini == config.OLE_LAST_BLOCK: iStreamSizeMini = None
        if iMSAT_1stSec    == config.OLE_LAST_BLOCK: iMSAT_1stSec    = None
        if iMSAT_TotalSec  == config.OLE_LAST_BLOCK: iMSAT_TotalSec  = None
        if iDISAT_1stSec   == config.OLE_LAST_BLOCK: iDISAT_1stSec   = None
        if iDISAT_TotalSec == config.OLE_LAST_BLOCK: iDISAT_TotalSec = None
        print("    SAT  Sec Size: %s" % str(iSectorSize))
        print("   MSAT  Sec Size: %s" % str(iSectorSizeMini))
        print("    SAT Total Sec: %s" % str(iSAT_TotalSec))
        print("    SAT  1st  Sec: %s" % str(iDir1stSec))
        print("      Stream Size: %s" % str(iStreamSizeMini))
        print("   MSAT  1st  Sec: %s" % str(iMSAT_1stSec))
        print("   MSAT Total Sec: %s" % str(iMSAT_TotalSec))
        print(" DirSAT  1st  Sec: %s" % str(iDISAT_1stSec))
        print(" DirSAT Total Sec: %s" % str(iDISAT_TotalSec))
    return


def printCache(strName, dictOLECache):
    print("          Name: %s" % strName)
    print("          Type: %d (%s)" % (dictOLECache["type"], config.OLE_BLOCK_TYPES[dictOLECache["type"]]))
    if (config.ARGS.verbose > 0):
        print("         Color: %d (%s)" % (dictOLECache["color"], "Black" if dictOLECache["color"] else "Red"))
        print("   Prev Dir ID: %s" % ("None" if (dictOLECache["PDID"] == config.OLE_NONE_BLOCK) else str(dictOLECache["PDID"])))
        print("   Next Dir ID: %s" % ("None" if (dictOLECache["NDID"] == config.OLE_NONE_BLOCK) else str(dictOLECache["NDID"])))
        print("   Sub  Dir ID: %s" % ("None" if (dictOLECache["SDID"] == config.OLE_NONE_BLOCK) else str(dictOLECache["SDID"])))
        print("      Class ID: " + dictOLECache["CID"])
        print("    User Flags: " + dictOLECache["userflags"])
        print("        Create: " + utils.getFormattedWinToPyTimeUTC(dictOLECache["create"]))
        print("        Modify: " + utils.getFormattedWinToPyTimeUTC(dictOLECache["modify"]))
        print("       1st Sec: %d" % dictOLECache["SID_firstSecDir"])
        print("          Size: %d" % dictOLECache["SID_sizeDir"])
        if (config.ARGS.edbfile != None):
            config.ESEDB.printInfo()
    return


def process(infile, fileThumbsDB, iThumbsDBSize):
    preparePILOutput()
    from PIL import Image, ImageChops

    if (config.ARGS.verbose >= 0):
        if (iThumbsDBSize % 512 ) != 0:
            sys.stderr.write(" Warning: Length of %s == %d not multiple 512\n" % (infile, iThumbsDBSize))

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

    tDB_endian = "<"  # Little Endian

    fileThumbsDB.seek(8)  # ...skip magic bytes                              # File Signature: 0xD0CF11E0A1B11AE1 for current version
    tDB_CLSID             = str(hexlify( fileThumbsDB.read(16) ))[2:-1]      # CLSID
    tDB_revisionNo        = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Minor Version
    tDB_versionNo         = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Version

    tDB_endianOrder       = fileThumbsDB.read(2)  # 0xFFFE OR 0xFEFF         # Byte Order, 0xFFFE (Intel)
    if (tDB_endianOrder == bytearray(config.BIG_ENDIAN)):
        tDB_endian = ">"  # Big Endian
    # Otherwise, it's Little Endian:
    #     (tDB_endianOrder == bytearray(config.LIL_ENDIAN))
    # which was initialized above.

    tDB_SectorSize         = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Sector Shift
    tDB_SectorSizeMini     = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # Mini Sector Shift
    reserved01             = unpack(tDB_endian+"H", fileThumbsDB.read(2))[0]  # short int reserved
    reserved02             = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # int reserved
    reserved03             = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count for Directory Chain (4 KB Sectors)
    tDB_SID_SAT_TotalSec   = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count for SAT Chain (512 B Sectors)
    tDB_SID_SAT_FirstSec   = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Root Directory: 1st Sector in Directory Chain
    reserved04             = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Signature for transactions (0, not implemented)
    tDB_StreamSize         = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Stream Max Size (typically 4 KB)
    tDB_SID_MSAT_FirstSec  = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # First Sector in the MiniSAT chain
    tDB_SID_MSAT_TotalSec  = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count in the MiniSAT chain
    tDB_SID_DISAT_FirstSec = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # First Sector in the DISAT chain
    tDB_SID_DISAT_TotalSec = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # Sector Count in the DISAT chain
    iOffset = 76

    if (config.ARGS.verbose >= 0):
        print(" Header\n --------------------")
        printHead(tDB_CLSID, tDB_revisionNo, tDB_versionNo, tDB_endian,
                     tDB_SectorSize, tDB_SectorSizeMini, tDB_SID_SAT_TotalSec, tDB_SID_SAT_FirstSec,
                     tDB_StreamSize, tDB_SID_MSAT_FirstSec, tDB_SID_MSAT_TotalSec,
                     tDB_SID_DISAT_FirstSec, tDB_SID_DISAT_TotalSec)
        print(config.STR_SEP)

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
        iCurrentSector = nextBlock(fileThumbsDB, listSAT, iCurrentSector, tDB_endian)

    # Load Mini SAT Streams list...
    iCurrentSector = tDB_SID_SAT_FirstSec  # First Entry (Root)
    iOffset = 512 + iCurrentSector * 512   # First Entry Offset (to Root)
    fileThumbsDB.seek(iOffset + 116)           # First Entry Offset + First Sec Offset (always Mini @ Root)
    iStream = unpack(tDB_endian+"L", fileThumbsDB.read(4))[0]  # First Mini SAT Entry (usually Mini's Catalog or OLE_LAST_BLOCK)
    listMiniSATStreams = []
    while (iStream != config.OLE_LAST_BLOCK):
        listMiniSATStreams.append(iStream)
        iStream = nextBlock(fileThumbsDB, listSAT, iStream, tDB_endian)

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
            strRawName = utils.decodeBytes(dictOLECache["nameDir"])[0:(dictOLECache["nameDirSize"] // 2 - 1)]

            # Empty Entry processing...
            # =============================================================
            if (dictOLECache["type"] == 0):
                if (config.ARGS.verbose >= 0):
                    print(" Empty Entry %d\n --------------------" % iStreamCounter)
                    printCache(strRawName, dictOLECache)
                    print(config.STR_SEP)

            # Storage Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 1):
                if (config.ARGS.verbose >= 0):
                    print(" Storage Entry %d\n --------------------" % iStreamCounter)
                    printCache(strRawName, dictOLECache)
                    print(config.STR_SEP)

            # Stream Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 2):
                bRegularBlock = (dictOLECache["SID_sizeDir"] >= 4096)

                if (config.ARGS.verbose >= 0):
                    print((" Stream Entry %d (" % iStreamCounter) +
                          ("Standard" if bRegularBlock else "Mini") + ")\n" +
                          " --------------------")
                    printCache(strRawName, dictOLECache)

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
                    iCurrentStreamSector = nextBlock(fileThumbsDB, listOfNext, iCurrentStreamSector, tDB_endian)

                iStreamDataLen = len(bstrStreamData)

                # Catalog Stream processing...
                # -------------------------------------------------------------
                #  Catalogs are related to the older Thumbs DB index name convention
                if (strRawName == "Catalog"):
                    if (config.ARGS.verbose >= 0):
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
                        strCatEntryTimestamp = utils.getFormattedWinToPyTimeUTC(iCatEntryTimestamp)
                        strCatEntryName      = utils.decodeBytes(bstrCatEntryName)
                        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                            strTarget = config.THUMBS_SUBDIR + "/" + strCatEntryID + ".jpg"
                            utils.setSymlink(strTarget, config.ARGS.outdir + strCatEntryName)

                            fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_SYMS, "a+")
                            fileURL.write(strTarget + " => " + strCatEntryName + "\n")
                            fileURL.close()

                        # Add a "catalog" entry...
                        tdbCatalog[iCatEntryID] = (strCatEntryTimestamp, strCatEntryName)

                        if (config.ARGS.verbose >= 0):
                            print("          " + ("% 4s" % strCatEntryID) + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strCatEntryName)

                        # Next catalog entry...
                        iCatOffset = iCatOffset + iCatEntryLen

                # Image Stream processing...
                # -------------------------------------------------------------
                else:
                    # Is End Of Image (EOI) at end of stream?
                    if (bstrStreamData[iStreamDataLen - 2: iStreamDataLen] != bytearray(config.JPEG_EOI)):  # ...Not End Of Image (EOI)
                        raise verror.EntryError(" Error (Entry): Missing End of Image (EOI) marker in stream entry " + str(iStreamCounter))

                    # --- Header 1: Get file offset...
                    headOffset   = unpack(tDB_endian+"L", bstrStreamData[ 0: 4])[0]
                    headRevision = unpack(tDB_endian+"L", bstrStreamData[ 4: 8])[0]

                    # Is length OK?
                    if (unpack(tDB_endian+"H", bstrStreamData[ 8:10])[0] != (iStreamDataLen - headOffset)):
                        raise verror.EntryError(" Error (Entry): Header 1 length mismatch in stream entry " + str(iStreamCounter))

                    strExt = "jpg"
                    if (not bOldNameID):
                        strFileName = None
                        if (config.ARGS.edbfile != None):
                            # ESEDB Search...
                            isESEDBRecFound = config.ESEDB.search(strRawName[strRawName.find("_") + 1: ])  # Raw Name is structured SIZE_THUMBCACHEID
                            if (isESEDBRecFound):
                                strCatEntryTimestamp = utils.getFormattedWinToPyTimeUTC(config.ESEDB.dictRecord["DATEM"])
                                if (config.ESEDB.dictRecord["IURL"] != None):
                                    strFileName = config.ESEDB.dictRecord["IURL"].split("/")[-1].split("?")[0]

                        if (strFileName != None):
                            if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                                strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strRawName + "." + strExt
                                utils.setSymlink(strTarget, config.ARGS.outdir + strFileName)

                                fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_SYMS, "a+")
                                fileURL.write(strTarget + " => " + strFileName + "\n")
                                fileURL.close()

                            # Add a "catalog" entry...
                            tdbCatalog[strRawName] = (strCatEntryTimestamp, strFileName)

                            if (config.ARGS.verbose >= 0):
                                print("  CATALOG " + strRawName + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strFileName)

                    # --- Header 2: Type 2 Thumbnail Image? (Full JPEG)...
                    if (bstrStreamData[headOffset: headOffset + 4] == bytearray(config.JPEG_SOI + config.JPEG_APP0)):
                        if (config.ARGS.outdir != None):
                            strFileName = tdbStreams.getFileName(keyStreamName, strExt)
                            fileImg = open(config.ARGS.outdir + strFileName, "wb")
                            fileImg.write(bstrStreamData[headOffset:])
                            fileImg.close()

                            if (config.ARGS.verbose > 0):
                                print("     File Info: ---------------------------------------")
                                print("          Type: 2 (Full JPEG)")
                                print("          Name: %s" % strFileName)

                        else:  # Not extracting...
                            tdbStreams[keyStreamName] = config.LIST_PLACEHOLDER

                    # --- Header 2: Type 1 Thumbnail Image? (JPEG Frame)...
                    elif (unpack(tDB_endian+"L", bstrStreamData[headOffset: headOffset + 4])[0] == 1):
                        # Is second header OK?
                        if (unpack(tDB_endian+"H", bstrStreamData[headOffset + 4: headOffset + 6])[0] != (iStreamDataLen - headOffset - 16)):
                            raise verror.EntryError(" Error (Entry): Header 2 length mismatch in stream entry " + str(iStreamCounter))

                        if (config.ARGS.outdir != None and config.THUMBS_TYPE_OLE_PIL):
                            strFileName = tdbStreams.getFileName(keyStreamName, strExt)
                            # DEBUG
                            #imageRaw = open(config.ARGS.outdir + strFileName + ".bin", "wb")
                            #imageRaw.write(bstrStreamData)
                            #imageRaw.close()

                            # --------------------------------------------------------------------------------
                            # Construct thumbnail image from standard JPEG blocks...
                            # --------------------------------------------------------------------------------
                            #
                            # [ 0: 8] Marker [0C 00 00 00 : 01 00 00 00]
                            # [ 8:12] Size of File 1 (SF1) from [12] to End Of File (little-endian)
                            # [12:16] Marker [01 00 00 00]
                            # [16:20] Size of File 2 (SF2) from [28] to End Of File (little-endian)
                            # [20:24] Frame Samples per Line (little-endian)
                            # [24:28] Frame Line Count (little-endian)
                            # [28:30] Start Of Image (SOI) [FF D8]
                            # [30:32] Start Of Frame (SOF) [FF C0] (8 + 3*FCC Bytes)
                            #   [32:34] Frame Length (FL) [20]
                            #   [34]    Frame Precision [8]
                            #   [35:37] Frame Line Count [96]
                            #   [37:39] Frame Samples per Line [96]
                            #   [39]    Frame Component Count (FCC: 3 Bytes Each) [4]
                            #     [40]    FC1: Component ID [R]
                            #     [41H]   FC1: Horiz Sample Factor: (bstrStreamData[41] >> 4) & 15 [1]
                            #     [41L]   FC1: Vert  Sample Factor:  bstrStreamData[41]       & 15 [1]
                            #     [42]    FC1: Quantization Table Selector [0]
                            #     [43]    FC2: Component ID [G]
                            #     [44H]   FC2: Horiz Sample Factor: (bstrStreamData[44] >> 4) & 15 [1]
                            #     [44L]   FC2: Vert  Sample Factor:  bstrStreamData[44]       & 15 [1]
                            #     [45]    FC2: Quantization Table Selector [0]
                            #     [46]    FC3: Component ID [B]
                            #     [47H]   FC3: Horiz Sample Factor: (bstrStreamData[47] >> 4) & 15 [1]
                            #     [47L]   FC3: Vert  Sample Factor:  bstrStreamData[47]       & 15 [1]
                            #     [48]    FC3: Quantization Table Selector [0]
                            #     [49]    FC4: Component ID [A]
                            #     [50H]   FC4: Horiz Sample Factor: (bstrStreamData[50] >> 4) & 15 [1]
                            #     [50L]   FC4: Vert  Sample Factor:  bstrStreamData[50]       & 15 [1]
                            #     [51]    FC4: Quantization Table Selector [0]
                            # [52:54] Start Of Scan (SOS) [FF DA]
                            # [54:12+SF1-2] ...Image Data...
                            # [12+SF1-2:12+SF1] End Of Image (EOI) [FF D9]
                            #
                            # As seem above, the JPEG data is a partial JPEG representation.  A full JPEG
                            # should have the following data blocks:
                            #   [FF D8]: Start of Image                      Bytes [28:30]
                            #   [FF E0]: Application Header        (MISSING)
                            #   [FF DB]: Define Quantization Table (MISSING)
                            #   [FF C0]: Start Of Frame                      Bytes [30:52]
                            #   [FF C4]: Define Huffman Table      (MISSING)
                            #   [FF DA]: Start Of Scan                       Bytes [52:...]
                            #   [FF D9]: End Of Image                        Bytes [Last-1:Last+1]
                            # Also, image elements are not as expected:
                            #   1. Image is flipped from top to bottom
                            #   2. For the color arrays:
                            #      a. the data is reported by the frames as RGBA but JPEG doesn't natively support RGBA.
                            #      b. the data reports (PIL assumes) the four color array is CMYK
                            #      c. the data is actually stored as YCCK (Y,Cb,Cr,K)
                            #   3. The K aray is inverted (255 - value) MOSTLY
                            #

                            iFileSize1 = int.from_bytes(bstrStreamData[ 8:12], 'little')
                            iFileSize2 = int.from_bytes(bstrStreamData[16:20], 'little')
                            iFileDiff = iFileSize1 - iFileSize2
                            iSIIndex = 0
                            while True:
                                if (bstrStreamData[iSIIndex : iSIIndex + 2] == bytearray(config.JPEG_SOI)):
                                    break
                                iSIIndex = iSIIndex + 1
                            iImageIndex = iSIIndex # Start of Image
                            iFrameIndex = iImageIndex + 2 # Start of Frame
                            iFrameSize = int.from_bytes(bstrStreamData[32:34], 'big')
                            iFramePrec = int(bstrStreamData[34])
                            iFrameLCnt = int.from_bytes(bstrStreamData[35:37], 'big')
                            iFrameSPL  = int.from_bytes(bstrStreamData[37:39], 'big')
                            iFrameCCnt = int(bstrStreamData[39])
                            iFrameCompID = [0 for i in range(iFrameCCnt)]
                            iFrameCompHF = [0 for i in range(iFrameCCnt)]
                            iFrameCompVF = [0 for i in range(iFrameCCnt)]
                            iFrameCompQT = [0 for i in range(iFrameCCnt)]
                            for i in range(iFrameCCnt):
                                iIndex = 40 + i * 3
                                iFrameCompID[i] = bstrStreamData[iIndex]
                                iFrameCompHF[i] = int((bstrStreamData[iIndex + 1] >> 4) & 0x0F)
                                iFrameCompVF[i] = int((bstrStreamData[iIndex + 1]) & 0x0F)
                                iFrameCompQT[i] = int(bstrStreamData[iIndex + 2])

                            iScanIndex = iFrameIndex + 2 + iFrameSize # Start Of Scan

                            bstrImage = (
                                config.THUMBS_TYPE_OLE_PIL_TYPE1_HEADER[:20] + # Generic JPEG Header
                                config.THUMBS_TYPE_OLE_PIL_TYPE1_QUANTIZE +    # Generic JPEG Quantization Table
                                bstrStreamData[iFrameIndex:iScanIndex] +       # Frame Info
                                config.THUMBS_TYPE_OLE_PIL_TYPE1_HUFFMAN  +    # Generic JPEG Huffman Tables
                                bstrStreamData[iScanIndex:] )                  # Image Info

                            imageIn = Image.open( BytesIO( bstrImage ), 'r', ["JPEG"] )

                            # Get assumed CMYK channels from image...
                            inChannelC, inChannelM, inChannelY, inChannelK = imageIn.split()
                            # Convert to actual CMYK channels...
                            outChannelC = inChannelY
                            outChannelM = inChannelM
                            outChannelY = inChannelC
                            w, h = inChannelK.size
                            outChannelK = Image.new('L', (w, h), 0)
                            #                               Y--------  Cb-------  Cr------
                            imageOut = Image.merge("CMYK", (outChannelC, outChannelM, outChannelY, outChannelK))
                            imageOut = imageOut.transpose(Image.FLIP_TOP_BOTTOM)
                            imageOut.save(config.ARGS.outdir + strFileName, "JPEG", quality=100)
                            #imageOut2 = Image.merge("YCbCr", (channelY, channelCb, channelCr))
                            #imageOut2 = imageOut2.transpose(Image.FLIP_TOP_BOTTOM)
                            #imageOut2.save(config.ARGS.outdir + strFileName + "_2", "JPEG", quality=100)

                            if (config.ARGS.verbose > 0):
                                print("     File Info: ---------------------------------------")
                                print("          Type: 1 (JPEG Fragment)")
                                print("          Name: %s" % strFileName)
                                if (config.ARGS.verbose > 1):
                                    print("        Size 1: %d Bytes" % iFileSize1)
                                    print("        Size 2: %d Bytes" % iFileSize2)
                                    print(" 16 Byte Diff?: %d Bytes, %s" % (iFileDiff, (iFileDiff == 16)))
                                    print("Start of Image: Byte# %d" % iImageIndex)
                                    print("Start of Frame: Byte# %d" % iFrameIndex)
                                    if (config.ARGS.verbose > 2):
                                        print("         Frame: --------------------")
                                        print("              :        Size: %d" % iFrameSize)
                                        print("              :   Precision: %d" % iFramePrec)
                                        print("              :  Line Count: %d" % iFrameLCnt)
                                        print("              : Sample/Line: %d" % iFrameSPL)
                                        print("              :  Components: %d" % iFrameCCnt)
                                        for i in range(iFrameCCnt):
                                            print("              : Entry -----: %d" % (i + 1))
                                            print("              :          ID: %c" % iFrameCompID[i])
                                            print("              :    H Factor: %d" % iFrameCompHF[i])
                                            print("              :    V Factor: %d" % iFrameCompVF[i])
                                            print("              : Quant Table: %d" % iFrameCompQT[i])
                                    print(" Start of Scan: Byte# %d (...Image Data...)" % iScanIndex)

                        else:  # Cannot extract (PIL not found) or not extracting...
                            tdbStreams[keyStreamName] = config.LIST_PLACEHOLDER
                    else:
                        raise verror.EntryError(" Error (Entry): Header 2 not found in stream entry " + str(iStreamCounter))

                if (config.ARGS.verbose >= 0):
                    print(config.STR_SEP)

            # Lock Bytes Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 3):
                if (config.ARGS.verbose >= 0):
                    print(" Lock Bytes Entry %d\n --------------------" % iStreamCounter)
                    printCache(strRawName, dictOLECache)
                    print(config.STR_SEP)

            # Property Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 4):
                if (config.ARGS.verbose >= 0):
                    print(" Property Entry %d\n --------------------" % iStreamCounter)
                    printCache(strRawName, dictOLECache)
                    print(config.STR_SEP)

            # Root Entry processing...
            # =============================================================
            elif (dictOLECache["type"] == 5):  # ...ROOT should always be first entry
                if (config.ARGS.verbose >= 0):
                    print(" Root Entry %d\n --------------------" % iStreamCounter)
                    printCache(strRawName, dictOLECache)
                    print(config.STR_SEP)

                if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
                    # Set the OLE Head for the HTTP report using the Root Entry info...
                    config.HTTP_REPORT.setOLE(dictOLECache)

            iStreamCounter += 1

        iCurrentSector = nextBlock(fileThumbsDB, listSAT, iCurrentSector, tDB_endian)

    # Process end of file...
    # -----------------------------------------------------------------
    if (config.ARGS.verbose > 0):
        if (tdbCatalog.isOutOfSequence()):
            sys.stderr.write(" Info: %s - Catalog index number out of usual sequence\n" % infile)

    if (config.ARGS.verbose > 0):
        if (tdbStreams.isOutOfSequence()):
            sys.stderr.write(" Info: %s - Stream index number out of usual sequence\n" % infile)

    astrStats = tdbStreams.extractStats()

    if (config.ARGS.verbose >= 0):
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

    if (config.ARGS.verbose >= 0):
        if (len(tdbCatalog) > 0):
            if (tdbCatalog.getCount() != tdbStreams.getCount()):
                sys.stderr.write(" Warning: %s - Counts (Catalog != Extracted)\n" % infile)
            else:
                if (config.ARGS.verbose > 0):
                    sys.stderr.write(" Info: %s - Counts (Catalog == Extracted)\n" % infile)
        else:
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: %s - No Catalog\n" % infile)
