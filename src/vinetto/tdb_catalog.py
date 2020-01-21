# -*- coding: UTF-8 -*-
"""
module tdb_catalog.py
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


from collections.abc import MutableMapping


###############################################################################
# Vinetto Thumb Database Catalog Class
###############################################################################
class TDB_Catalog(MutableMapping):
    def __init__(self, data=()):
        # Initialize a new TDB_Catalog instance...
        self.__tdbCatalog = {}  # {iKey, [(strTime, strName)]}
        self.__bOutOfSeq = False
        self.__iPreviousID = None
        self.__iCount = 0
        self.update(data)
        return


    def __getitem__(self, key):
        return self.__tdbCatalog[key]


    def __delitem__(self, key):
        self.__iCount -= len(self[key])
        del self.__tdbCatalog[key]
        return


    def __setitem__(self, key, value):
        # Add a new Catalog entry...
        if not isinstance(key, int):
            raise ValueError("Not integer: Catalog key must be an integer!")
        bList = isinstance(value, list)
        bTuple = isinstance(value, tuple)
        if not (bList or bTuple):
            raise TypeError("Not list or tuple: Catalog value must be a list of 2-tuples or a 2-tuple!")
        listVal = value
        if bTuple:
            listVal = [value]
        for tupleItem in listVal:
            if not isinstance(tupleItem, tuple):
                raise TypeError("Not tuple: Catalog value must be a list of 2-tuples or a 2-tuple!")
            if (len(tupleItem) != 2):
                raise ValueError("Not 2-tuple: Catalog value must be a list of 2-tuples or a 2-tuple!")
            if not isinstance(tupleItem[0], str):
                raise ValueError("Not a string: Catalog 2-tuples must have string (timestamp) for index 0!")
            if not isinstance(tupleItem[1], str):
                raise ValueError("Not a string: Catalog 2-tuples must have string (name) for index 1!")

        bKeyExists = bool(key in self.__tdbCatalog)
        if bTuple:  # value is a single 2-tuple, append!...
            if bKeyExists:
                self.__tdbCatalog[key].append(value)
            else:
                self.__tdbCatalog[key] = listVal
            self.__iCount += 1
        else:  # value is a list of 2-tuples, replace!...
            if bKeyExists:
                del self[key]
            self.__tdbCatalog[key] = listVal
            self.__iCount += len(listVal)

        if (self.__iPreviousID != None):
            if (key != self.__iPreviousID + 1):
                self.__bOutOfSeq = True
        self.__iPreviousID = key

        return


    def __iter__(self):
        return iter(self.__tdbCatalog)


    def __len__(self):
        return len(self.__tdbCatalog)


    def __repr__(self):
        return f"{type(self).__name__}({self.__tdbCatalog})"


    def getCount(self):
        # Return number of Catalog entries...
        return self.__iCount


    def get(self, iCat):
        # Return iCat Catalog entry...
        if iCat in self.__tdbCatalog:
            return self.__tdbCatalog[iCat]
        return None


    def getOrphans(self, tdbStreams):
        # Return orphan Catalog entries (not in current stream)...
        listOrphanIDs = []
        for iID in self.__tdbCatalog:
            if (not iID in tdbStreams):
                listOrphanIDs.append(iID)
        return listOrphanIDs


    def isOutOfSequence(self):
        # Return self.__bOutOfSeq value...
        return self.__bOutOfSeq


