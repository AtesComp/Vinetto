# -*- coding: UTF-8 -*-
"""
module tdb_streams.py
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
file_micro = "0"


import vinetto.config as config

from collections.abc import MutableMapping


###############################################################################
# Vinetto Thumb Database Catalog Class
###############################################################################
class TDB_Streams(MutableMapping):
    def __init__(self, data=()):
        # Initialize a new TDB_Streams instance...
        self.__tdbStreams = {}  # {iKey/strKey, [ [strIndexExt], bStreamID, [(iIndexType, strIndexFileName)] ] }
        self.__bOutOfSeq = False
        self.__iPreviousID = None
        self.__dictCount = {"All": 0, 1: 0, 2: 0}
        self.update(data)

    def __getitem__(self, key):
        return self.__tdbStreams[key]


    def __delitem__(self, key):
        for tupleIndex in self[key][2]:
            self.__dictCount["All"] -= 1
            self.__dictCount[tupleIndex[0]] -= 1
        del self.__tdbStreams[key]


    def __setitem__(self, key, value):
        # Add or append a Stream entry...
        # value => [strIndexExt, (iIndexType, strIndexFileName)] }

        iStreamID = None
        bStreamID = None
        strGivenFileName = None
        if isinstance(key, int):
            iStreamID = key
            bStreamID = True
        elif isinstance(key, str):
            strGivenFileName = key
            bStreamID = False
        else:
            raise TypeError("Not invalid: Stream key must be a StreamID integer or a FileName string!")

        if (not isinstance(value, list)):
            raise TypeError("Not list: Stream value must be a list of 2 items - file extension string and 2-tuple!")
        if (len(value) != 2):
            raise ValueError("Not 2 items: Stream value must be a list of 2 items - file extension string and 2-tuple!")
        if not isinstance(value[0], str):
            raise TypeError("Not string: Stream value[0] must be a file extension string!")
        if not isinstance(value[1], tuple):
            raise TypeError("Not 2-tuple: Stream value[1] must be a 2-tuple!")
        if (len(value[1]) != 2):
            raise ValueError("Not 2-tuple: Stream value[1] must be a 2-tuple!")
        if not isinstance(value[1][0], int):
            raise ValueError("Not integer: Stream value[1] 2-tuple must have integer (index type) for index 0!")
        if not isinstance(value[1][1], str):
                raise ValueError("Not string: Stream value[1] 2-tuple must have string (filename) for index 1!")

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
        self.__dictCount["All"] += 1
        self.__dictCount[value[1][0]] += 1

        if (bStreamID):  # Stream ID...
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
        return f"{type(self).__name__}({self.__tdbStreams})"


    def getCount(self, iType = "All"):
        # Return number of Catalog entries based on type...
        return self.__dictCount[iType]


    def get(self, key):
        # Return iCat Catalog entry...
        if key in self.__tdbStreams:
            return self.__tdbStreams[key]
        return None


    def isOutOfSequence(self):
        # Return self.__bOutOfSeq value...
        return self.__bOutOfSeq


    def getFileName(self, keyStreamName, strExt, bHasSymName, iType):
        strPrefix = ""
        if (bHasSymName and config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                strPrefix = config.THUMBS_SUBDIR + "/"

        if bHasSymName:
            # Compute filename from the Stream ID for a thumbnail...
            strComputedFileName = "%d" % keyStreamName
        else:
            # Compute filename from the given filename for a thumbnail...
            strComputedFileName = keyStreamName

        # Is the key already indexed?
        if (keyStreamName in self.__tdbStreams):
            # Compute the next valid filename for a given filename...
            # FORMAT: XXX_# where XXX is either a given filename that may include '_'s
            #                                or a Stream ID that has no '_'s
            #                   and # is an increment value for existing filenames

            # Get first stored name without number sequence ("name")...
            (iIndexType, strIndexFileName) = self.__tdbStreams[keyStreamName][2][0]
            if (strComputedFileName == strIndexFileName):
                if (len(self.__tdbStreams[keyStreamName][2]) == 1):
                    strComputedFileName = strIndexFileName + "_1"
                else:
                    # Get last stored name with highest number sequence ("name_#")...
                    (iIndexType, strIndexFileName) = self.__tdbStreams[keyStreamName][2][-1]
                    iMark = strIndexFileName.rfind("_")
                    try:
                        iVal = int(strIndexFileName[iMark + 1: ])
                    except ValueError:
                        raise Value("Stream invalid: Stream names must be extended with _# where # is an integer! Offender: %s" % strIndexFileName)
                    strComputedFileName = strIndexFileName[ :iMark + 1] + str(iVal + 1)

        # Add or append to self...
        self[keyStreamName] = [strExt, (iType, strComputedFileName)]
        # Return filename...
        return strPrefix + strComputedFileName + "." + strExt


    def extractStats(self):
        if (self.__tdbStreams == {}):
            return None

        # Return extraction statistics...
        dictStats = {"u": {1: 0, 2: 0}, "e": {1: 0, 2: 0} }
        for key in self.__tdbStreams:
            for (iIndexType, strIndexFileName) in self.__tdbStreams[key][2]:
                if (strIndexFileName == ""):
                    dictStats["u"][iIndexType] += 1
                else:
                    dictStats["e"][iIndexType] += 1

        strExtSuffix = ""
        if config.ARGS.outdir != None:
            strExtSuffix = " to " + config.ARGS.outdir

        astrStats = []
        for strExtractType in dictStats:
            for iType in dictStats[strExtractType]:
                if (dictStats["u"][iType] == 0 and dictStats["e"][iType] == 0):
                    continue
                strStat = ""
                if (strExtractType == "u"):
                    strStat += "Unextracted: "
                else:
                    strStat += "  Extracted: "
                strStat += ("%4d" % dictStats[strExtractType][iType]) + " thumbnails of Type " + str(iType)
                if (strExtractType == "e"):
                    strStat += strExtSuffix
                astrStats.append(strStat)

        return astrStats


