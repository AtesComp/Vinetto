# -*- coding: UTF-8 -*-
"""
module tdb_streams.py
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
file_micro = "5"


import sys

from collections.abc import MutableMapping
import vinetto.config as config

unicode = str



###############################################################################
# Vinetto Thumb Database Catalog Class
# Input: iKey/strKey, [strIndexExt, strIndexFileName]
# Store: {iKey/strKey, [strIndexExt], bStreamID, [strIndexFileName] ] }
###############################################################################
class TDB_Streams(MutableMapping):
    def __init__(self, data=()):
        # Initialize a new TDB_Streams instance...
        self.__tdbStreams = {}  # {iKey/strKey, [ [strIndexExt], bStreamID, [strIndexFileName] ] }
        self.__bOutOfSeq = False
        self.__iPreviousID = None
        self.__dictCount = 0
        self.update(data)

    def __getitem__(self, key):
        return self.__tdbStreams[key]


    def __delitem__(self, key):
        for tupleIndex in self[key][2]:
            self.__dictCount -= 1
        del self.__tdbStreams[key]


    def __testStreamID__(self, key):
        bStreamID = None
        if isinstance(key, int):
            bStreamID = True
        elif isinstance(key, unicode):
            bStreamID = False
        else:
            raise TypeError("Invalid: Stream key must be an integer or string representing a thumbnail ID/name!")
        return bStreamID


    def __setitem__(self, key, value):
        # Add or append a Stream entry...
        # value => [strIndexExt, strIndexFileName] }

        bStreamID = self.__testStreamID__(key)

        if (not isinstance(value, list)):
            raise TypeError("Not list: Stream value must be a list of 2 items - file extension string and file name string!")
        if (len(value) != 2):
            raise ValueError("Not 2 items: Stream value must be a list of 2 items - file extension string and file name string!")
        if not (isinstance(value[0], str) or isinstance(value[0], unicode)):
            raise TypeError("Not string: Stream value[0] must be a file extension string!")
        if not (isinstance(value[1], str) or isinstance(value[1], unicode)):
            raise TypeError("Not string: Stream value[1] must be a file name string!")

        if (key in self.__tdbStreams):  # ...append a Stream entry...
            if (not value[0] in self.__tdbStreams[key][0]):  # ...append ext...
                self.__tdbStreams[key][0].append(value[0])
                sys.stderr.write(" Warning: Stream \"%s\" has more than one file extension" % (("%d" % key) if bStreamID else key))
            if (bStreamID != self.__tdbStreams[key][1]):  # ...change bool...
                self.__tdbStreams[key][1] = bStreamID
                sys.stderr.write(" Warning: Stream \"%s\" has changed Stream ID boolean to %s" % (("%d" % key) if bStreamID else key), bStreamID)
            self.__tdbStreams[key][2].append(value[1])
        else:  # ...add a new Stream entry...
            self.__tdbStreams[key] = [ [ value[0] ], bStreamID, [ value[1] ] ]
        self.__dictCount += 1

        if (bStreamID):  # Stream ID, key is int...
            if (self.__iPreviousID != None):
                if (key != self.__iPreviousID + 1):
                    self.__bOutOfSeq = True
            self.__iPreviousID = key

        return


    def __iter__(self):
        return iter(self.__tdbStreams)


    def __len__(self):
        return len(self.__tdbStreams)


    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, self.__tdbStreams)


    def getCount(self):
        # Return number of Catalog entries based on type...
        return self.__dictCount


    def get(self, key):
        # Return iCat Catalog entry...
        if key in self.__tdbStreams:
            return self.__tdbStreams[key]
        return None


    def isOutOfSequence(self):
        # Return self.__bOutOfSeq value...
        return self.__bOutOfSeq


    def getFileName(self, key, strExt):
        bStreamID = self.__testStreamID__(key)

        strPrefix = ""
        if (bStreamID and config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                # Put real file in the thumbnail subdirectory...
                #  Symlinks in the top dir will point to the real file here
                strPrefix = config.THUMBS_SUBDIR + "/"

        # Default filename from the given filename for a thumbnail...
        #  NOTE: Filename same as key
        strComputedFileName = key
        if bStreamID:
            # Default older filename from the Stream ID for a thumbnail...
            strComputedFileName = "%d" % key

        # Is the key already indexed?
        if (key in self.__tdbStreams):
            # Compute the next valid filename for a given filename...
            # FORMAT: XXX_# where XXX is either a given filename (str) that may include '_'s
            #                                or a Stream ID (int) that has no '_'s
            #                   and # is an increment value for existing filenames

            # Get first stored name - the clean name without number sequence (XXX)...
            strIndexFileName = self.__tdbStreams[key][2][0]
            if (strComputedFileName == strIndexFileName):  # ...same as first (duplicate)?
                if (len(self.__tdbStreams[key][2]) == 1):  # ...only 1 stored?
                    strComputedFileName = strIndexFileName + "_1"
                else:  # ...more than 1 stored...
                    # Get last stored name with highest number sequence ("XXX_#")...
                    strIndexFileName = self.__tdbStreams[key][2][-1]
                    iMark = strIndexFileName.rfind("_")
                    try:
                        iVal = int(strIndexFileName[iMark + 1: ])
                    except ValueError:
                        tb = sys.exc_info()[2]
                        strError = "Invalid Stream: Stream names must be extended with _# where # is an integer! Offender: {}".format(strIndexFileName)
                        raise ValueError(strError).with_traceback(tb)
                    strComputedFileName = strIndexFileName[ :iMark + 1] + str(iVal + 1)

        # Add or append to self -- see __setitem__()...
        self[key] = [strExt, strComputedFileName]
        # Return filename...
        return strPrefix + strComputedFileName + "." + strExt


    def extractStats(self):
        if (self.__tdbStreams == {}):
            return None

        # Return extraction statistics...
        dictStats = {"u": 0, "e": 0 }
        for key in self.__tdbStreams:
            for strIndexFileName in self.__tdbStreams[key][2]:
                if (strIndexFileName == ""):
                    dictStats["u"] += 1
                else:
                    dictStats["e"] += 1

        strExtSuffix = ""
        if config.ARGS.outdir != None:
            strExtSuffix = " to " + config.ARGS.outdir

        astrStats = []
        if (dictStats["u"] > 0):
            strStat = "Unextracted: %4d thumbnails" % dictStats["u"]
            astrStats.append(strStat)
        if (dictStats["e"] > 0):
            strStat = "  Extracted: %4d thumbnails" % dictStats["e"] + strExtSuffix
            astrStats.append(strStat)
        if (len(astrStats) == 0):
            return None

        return astrStats


