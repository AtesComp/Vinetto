# -*- coding: UTF-8 -*-
"""
module vinutils.py
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
__minor__ = "3"
__micro__ = "3"
__maintainer__ = "Keven L. Ates"
__author__ = "Michel Roukine"
__location__ = "https://github.com/AtesComp/Vinetto"

from time import strftime, gmtime

TN_CATALOG = {}
bCATALOG_INDEX_OUT_OF_SEQ = False
iCATALOG_PREVIOUS_ID = None

TN_STREAMS = {}
bSTREAMS_INDEX_OUT_OF_SEQ = False
iSTREAMS_PREVIOUS_ID = None

LAST_BLOCK = 4294967294 # unsigned -2
NONE_BLOCK = 4294967295 # unsigned -1


def isCatalogOutOfSequence():
    # Return bCATALOG_INDEX_OUT_OF_SEQ value...
    return bCATALOG_INDEX_OUT_OF_SEQ


def isStreamsOutOfSequence():
    # Return bSTREAMS_INDEX_OUT_OF_SEQ value...
    return bSTREAMS_INDEX_OUT_OF_SEQ


def addCatalogEntry(iCatEntryId, strCatEntryTimestamp, strCatEntryName):
    # Add a new Catalog entry...
    global TN_CATALOG, bCATALOG_INDEX_OUT_OF_SEQ, iCATALOG_PREVIOUS_ID

    if iCATALOG_PREVIOUS_ID != None:
        if iCatEntryId != (iCATALOG_PREVIOUS_ID + 1) :
            bCATALOG_INDEX_OUT_OF_SEQ = True

    if iCatEntryId in TN_CATALOG:
        TN_CATALOG[iCatEntryId].append((strCatEntryTimestamp, strCatEntryName))
    else:
        TN_CATALOG[iCatEntryId] = [(strCatEntryTimestamp, strCatEntryName)]

    iCATALOG_PREVIOUS_ID = iCatEntryId
    return


def addStreamIdToStreams(iStreamId, iIndexType, strIndexFileName):
    global TN_STREAMS, bSTREAMS_INDEX_OUT_OF_SEQ, iSTREAMS_PREVIOUS_ID

    # Add new thumbnail stream reference for Stream Id...
    if iSTREAMS_PREVIOUS_ID != None:
        if iStreamId != (iSTREAMS_PREVIOUS_ID + 1) :
            bSTREAMS_INDEX_OUT_OF_SEQ = True

    if iStreamId in TN_STREAMS:
        TN_STREAMS[iStreamId].append((iIndexType, strIndexFileName, True))
    else:
        TN_STREAMS[iStreamId] = [(iIndexType, strIndexFileName, True)]

    iSTREAMS_PREVIOUS_ID = iStreamId
    return


def addFileNameToStreams(strGivenFileName, iIndexType, strIndexFileName):
    global TN_STREAMS

    # Add new thumbnail stream reference for given filename...
    if strGivenFileName in TN_STREAMS:
        TN_STREAMS[strGivenFileName].append((iIndexType, strIndexFileName, False))
    else:
        TN_STREAMS[strGivenFileName] = [(iIndexType, strIndexFileName, False)]

    return


def countCatalogEntry():
    # Return number of Catalog entries...
    iCount = 0
    for listFileNames in TN_CATALOG:
        iCount += len(TN_CATALOG[listFileNames])
    return iCount


def countThumbnails(iType = 0):
    global TN_STREAMS

    # Return number of extracted/unextracted thumbnails...
    iCount = 0
    for aIndexDir in TN_STREAMS:
        if (iType == 0): # ...count everything
            iCount += len(TN_STREAMS[aIndexDir])
        else: # ...count the given type
            for (iIndexType, strIndexFileName, bStreamId) in TN_STREAMS[aIndexDir]:
                if (iType == iIndexType):
                    iCount += 1
    return iCount


def extractStats(strDirectory):
    global TN_STREAMS

    if (TN_STREAMS == {}):
        return None

    # Return extraction statistics...
    dicStats = {"u": {1: 0, 2: 0}, "e": {1: 0, 2: 0} }
    for aIndexDir in TN_STREAMS:
        for (iIndexType, strIndexFileName, bStreamId) in TN_STREAMS[aIndexDir]:
            if (strIndexFileName == ""):
                dicStats["u"][iIndexType] += 1
            else:
                dicStats["e"][iIndexType] += 1

    strExtSuffix = ""
    if strDirectory != None:
        strExtSuffix = " to " + strDirectory

    astrStats = []
    for strExtractType in dicStats:
        for iType in dicStats[strExtractType]:
            if (dicStats["u"][iType] == 0 and dicStats["e"][iType] == 0):
                continue
            strStat = ""
            if (strExtractType == "e"):
                strStat += "  Extracted: "
            else:
                strStat += "Unextracted: "
            strStat += str(dicStats[strExtractType][iType]) + " thumbnails of Type " + str(iType)
            if (strExtractType == "e"):
                strStat += strExtSuffix
            astrStats.append(strStat)

    return astrStats


def getCatalogEntry(iCat):
    # Return iCat Catalog entry...
    if iCat in TN_CATALOG:
        return TN_CATALOG[iCat]
    return []


def nextIndexedFileName(strFileName):
    # Compute the next valid filename for a given filename...
    # FORMAT: XXX_NNN where XXX is either a given filename that may include '_'s
    #                                  or a Stream Id that has no '_'s
    #                   and MMM is an increment value for existing filenames
    iMark = strFileName.rfind("_")
    if (iMark < 0):
        return strFileName + "_1"

    try:
        iVal = int(strFileName[iMark + 1: ])
    except ValueError:
        # NOTE: This exception should not happen for Stream Ids
        return strFileName + "_1"

    return ( strFileName[ :iMark + 1] + str(iVal + 1) )


def getStreamFileName(iStreamId, iType):
    global TN_STREAMS

    # Compute filename from the Stream Id for a thumbnail...
    strComputedFileName = "%d" % iStreamId

    # Is the Stream Id already indexed?
    if iStreamId in TN_STREAMS:
        for (iIndexType, strIndexFileName, bStreamId) in TN_STREAMS[iStreamId]:
            if strComputedFileName == strIndexFileName:
                strComputedFileName = nextIndexedFileName(strIndexFileName)
    addStreamIdToStreams(iStreamId, iType, strComputedFileName)
    return strComputedFileName


def getRawFileName(strGivenFileName, iType):
    global TN_STREAMS

     # Compute filename from the given filename for a thumbnail...
    strComputedFileName = strGivenFileName

    # Is the given filename already indexed?
    if strGivenFileName in TN_STREAMS:
        for (iIndexType, strIndexFileName, bStreamId) in TN_STREAMS[strGivenFileName]:
            if strComputedFileName == strIndexFileName:
                strComputedFileName = nextIndexedFileName(strIndexFileName)
    addFileNameToStreams(strGivenFileName, iType, strComputedFileName)
    return strComputedFileName


def convertToPyTime(iFileTime_Win32):
    # Convert Win32 timestamp to Python timestamp...
    SECS_BETWEEN_EPOCHS = 11644473600
    SECS_TO_100NS = 10000000

    iFileTime = 0
    if iFileTime_Win32 != 0:
        iFileTime = (iFileTime_Win32 // SECS_TO_100NS) - SECS_BETWEEN_EPOCHS
    return iFileTime

def getFormattedTimeUTC(iTime):
    strTime = strftime("%Y-%m-%dT%H:%M:%S Z", gmtime(iTime))
    return strTime
