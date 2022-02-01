# -*- coding: UTF-8 -*-
"""
module esedb.py
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
file_micro = "8"


import sys
from struct import unpack
from binascii import hexlify, unhexlify

import vinetto.config as config
import vinetto.utils as utils
import vinetto.error as verror


###############################################################################
# Vinetto ESEDB Class
###############################################################################
class ESEDB():
    def __init__(self):
        # Initialize a new ESEDB instance...

        #  Windows Search (Windows.edb) Extensible Storage Engine (ESE) database:
        #    Windows 7:
        #      C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
        #
        #    The Windows.edb stores the ThumbnailCacheID as part of its metadata for indexed files.
        #    Uses ESEDB library pyesedb to read the EDB file.
        #
        self.edbFile     = False  # Opened Windows.edb or equivalent user specified file, see config.ARGS.edbfile
        self.table       = None   # Opened SystemIndex_0A or SystemIndex_PropertyStore table from edbFile
        self.listRecords = None   # Image records from table
        self.dictRecord  = None   # Image record found in listRecords

        self.iColNames = {
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

        self.iCol = {}
        for key in self.iColNames.keys():
            self.iCol[key] = None

    def prepare(self):
        bEDBFileGood = False
        try:
            import pyesedb
            sys.stdout.write(" Info: Imported system pyesedb library.")
            bEDBFileGood = True
        except:
            sys.stdout.write(" Warning: Cannot import system pyesedb library!")
            # Error!  The "pyesedb" library is supposed to be installed locally with Vinetto,
            try:
                from vinetto.lib import pyesedb
                sys.stdout.write(" Info: Imported Vinetto's pyesedb library.")
                bEDBFileGood = True
            except:
                # Error!  The "pyesedb" library is not found anywhere.
                sys.stdout.write(" Warning: Cannot import Vinetto's pyesedb library!")
                # A missing "pyesedb" library is bad!
                raise verror.InstallError(" Error (Install): Cannot import a pyesedb library!")

        pyesedb_ver = pyesedb.get_version()
        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: Imported pyesedb version %s\n" % pyesedb_ver)

        # Open ESEDB file...
        try:
            self.edbFile = pyesedb.file()
            self.edbFile.open(config.ARGS.edbfile)
        except IOError:
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: Cannot opened ESEDB File for enhanced processing\n")
            self.edbFile = False
            return self.edbFile

        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: Opened ESEDB file %s\n" % config.ARGS.edbfile)

    #    # TEST Get Tables...
    #    iTblCnt = self.edbFile.get_number_of_tables()
    #    sys.stderr.write(" DBG: Got %d tables\n" % iTblCnt)
    #    for iTbl in range(iTblCnt):
    #        table = self.edbFile.get_table(iTbl)
    #        if (table == None):
    #            sys.stderr.write(" DBG:   Table %d is None\n" % iTbl)
    #            continue
    #        strTblName = table.get_name()
    #        sys.stderr.write(" DBG:   Table %d Name %s\n" % (iTbl, strTblName))

        strSysIndex = "SystemIndex_"
        strTableName = "PropertyStore"
        self.table = self.edbFile.get_table_by_name(strSysIndex + strTableName)
        if (self.table == None):  # ...try older table name...
            strTableName = "0A"
            self.table = self.edbFile.get_table_by_name(strSysIndex + strTableName)
        if (self.table == None):  # ...still no table available?...
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: Cannot opened ESEDB Table for enhanced processing\n")
            self.edbFile.close()
            self.edbFile = False
            return self.edbFile

        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: Opened ESEDB Table %s%s for enhanced processing\n" % (strSysIndex, strTableName))

        iColCnt = self.table.get_number_of_columns()
        if (config.ARGS.verbose > 1):
            sys.stderr.write(" Info:     ESEDB %d avaliable columns\n" % iColCnt)
        iColCntFound = 0
        for iCol in range(iColCnt):
            column = self.table.get_column(iCol)
            strColName = column.get_name()
            for strKey in self.iColNames:
                if (strColName.endswith(self.iColNames[strKey][0])):
                    self.iCol[strKey] = iCol  # ...column number for column name
                    iColCntFound += 1

            if (iColCntFound == len(self.iColNames)):  # Total Columns searched
                break

        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info:     ESEDB %d columns of %d possible\n" % (iColCntFound, len(self.iColNames)))
            if (config.ARGS.verbose > 1):
                for strKey in self.iColNames:
                    if (self.iCol[strKey] != None):
                        sys.stderr.write(" Info:         Found column \"" + strKey + "\"\n")

        return True


    def processRecord(self, recordESEDB, strKey):
        rawESEDB = None
        iCol = self.iCol[strKey]
        if (iCol == None):
            return rawESEDB

        cTest = self.iColNames[strKey][1]
        # Format the key's value for output...
        # 'x' - bstr  == (Large) Binary Data
        # 's' - str   == (Large) Text
        # 'i' - int   == Integer (32/16/8)-bit (un)signed
        # 'b' - bool  == Boolean or Boolean Flags (Integer)
        # 'f' - float == Floating Point (Double Precision) (64/32-bit)
        # 'd' - date  == Binary Data converted to Formatted UTC Time
        if   (cTest == 'x'):
            rawESEDB = recordESEDB.get_value_data(iCol)
        elif (cTest == 's'):
            rawESEDB = recordESEDB.get_value_data_as_string(iCol)
        elif (cTest == 'i'):
            rawESEDB = recordESEDB.get_value_data_as_integer(iCol)
        elif (cTest == 'b'):
            rawESEDB = recordESEDB.get_value_data_as_integer(iCol)
            if (rawESEDB == None or rawESEDB == 0):  # ...convert integer to boolean False
                rawESEDB = False
            elif (rawESEDB == 1 or rawESEDB == -1):  # ...convert integer to boolean True
                rawESEDB = True
            else:  # Setup Flag Display for integer flags
                if (rawESEDB < -2147483648):     # ...convert negative 64 bit integer to positive
                    rawESEDB = rawESEDB & 0xffffffffffffffff
                if (rawESEDB < -32768):          # ...convert negative 32 bit integer to positive
                    rawESEDB = rawESEDB & 0xffffffff
                if (rawESEDB < -128):            # ...convert negative 16 bit integer to positive
                    rawESEDB = rawESEDB & 0xffff
                if (rawESEDB < 0):               # ...convert negative 8 bit integer to positive
                    rawESEDB = rawESEDB & 0xff
        elif (cTest == 'f'):
            rawESEDB = recordESEDB.get_value_data_as_floating_point(iCol)
        elif (cTest == 'd'):
            rawESEDB = recordESEDB.get_value_data(iCol)
            if (rawESEDB == None):
                rawESEDB = 0
            else:
                rawESEDB = unpack("<Q", rawESEDB)[0]
        return rawESEDB


    def load(self):
        if (self.iCol["TCID"] == None):
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: No ESEDB Image column %s available\n" % utils.ESEDB_ICOL_NAMES["TCID"][0])
            self.table = None
            self.edbFile.close()
            self.edbFile = False
            return self.edbFile
        if (self.iCol["MIME"] == None and self.iCol["CTYPE"] == None and self.iCol["ITT"] == None):
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: No ESEDB Image columns %s available\n" %
                                (utils.ESEDB_ICOL_NAMES["MIME"][0] + ", " +
                                utils.ESEDB_ICOL_NAMES["CTYPE"][0] + ", or " +
                                utils.ESEDB_ICOL_NAMES["ITT"][0]))
            self.table = None
            self.edbFile.close()
            self.edbFile = False
            return self.edbFile

        self.listRecords = []

        if (config.ARGS.verbose > 1):
            sys.stderr.write(" Info:     ESEDB Getting record count...\n")
        iRecCnt = self.table.get_number_of_records()

        if (config.ARGS.verbose > 1):
            sys.stderr.write(" Info:     ESEDB Processing records...\n")

        strRecIPD = None
        strRecIU = None
        iRecAdded = 0
        strRecOut = " Info:         Record #: %d Added: %d\r"

        # Read all the records...
        for iRec in range(iRecCnt):
            record = self.table.get_record(iRec)
            if (record == None):
                break
            if (config.ARGS.verbose > 1 and (iRec + 1) % 1000 == 0):
                sys.stderr.write(strRecOut % (iRec + 1, iRecAdded))
                sys.stderr.flush()

            # Test for ThumbnailCacheId exists...
            bstrRecTCID = record.get_value_data(self.iCol["TCID"])
            if (bstrRecTCID == None):
                continue

            # Test for image type record...
            strMime = ""
            if (self.iCol["MIME"] != None):
                strMime = (record.get_value_data_as_string(self.iCol["MIME"]) or "")
            strCType = ""
            if (self.iCol["CTYPE"] != None):
                strCType = (record.get_value_data_as_string(self.iCol["CTYPE"]) or "")
            strITT = ""
            if (self.iCol["ITT"] != None):
                strITT = (record.get_value_data_as_string(self.iCol["ITT"]) or "")
            strImageTest = strMime + strCType + strITT
            if (not "image" in strImageTest):
                continue

    #        # TEST Record Retrieval...
    #        print("\nTCID: " + str( hexlify( bstrRecTCID ))[2:-1])
    #        for strKey in self.iColNames:
    #            if (strKey == "TCID"):
    #                continue
    #            sys.stdout.write(strKey + ": ")
    #            rawESEDB = self.processRecord(record, strKey)
    #            print(rawESEDB)

            dictRecord = {}
            dictRecord["TCID"]  = bstrRecTCID
            dictRecord["MIME"]  = strMime
            dictRecord["CTYPE"] = strCType
            dictRecord["ITT"]   = strITT

            for strKey in self.iColNames:
                if (strKey == "TCID" or strKey == "MIME" or strKey == "CTYPE" or strKey == "ITT"):
                    continue
                dictRecord[strKey] = self.processRecord(record, strKey)

            self.listRecords.append(dictRecord)
            iRecAdded += 1
            if (config.ARGS.verbose > 1):
                sys.stderr.write(strRecOut % (iRec + 1, iRecAdded))
                sys.stderr.flush()

        if (config.ARGS.verbose > 1):
            sys.stderr.write(strRecOut % (iRec + 1, iRecAdded))
            sys.stderr.write("\n")

    #    # TEST: Print ESEDB Image Records...
    #    for dictRecord in self.listRecords:
    #        self.printInfo(False)
    #        print()

        if (len(self.listRecords) == 0):
            self.listRecords = None
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: No ESEDB Image data available\n")
            self.table = None
            self.edbFile.close()
            self.edbFile = False
            return self.edbFile

        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info:     ESEDB Image data loaded\n")

        self.table = None
        self.edbFile.close()
        self.edbFile = True  # ...ESEDB records were loaded, see self.listRecords
        return self.edbFile


    def getStr(self, strKey):
        strESEDB = None
        if (self.dictRecord == None):
            return strESEDB
        dataESEDB = None
        iCol = self.iCol[strKey]
        if (iCol != None):
            cTest = self.iColNames[strKey][1]
            # Format the key's value for output...
            # 'x' - bstr  == (Large) Binary Data
            # 's' - str   == (Large) Text
            # 'i' - int   == Integer (32/16/8)-bit (un)signed
            # 'b' - bool  == Boolean or Boolean Flags (Integer)
            # 'f' - float == Floating Point (Double Precision) (64/32-bit)
            # 'd' - date  == Binary Data converted to Formatted UTC Time

            if   (cTest == 'x'):
                strESEDB = str( hexlify( self.dictRecord[strKey] ))[2:-1]  # ...stript off start b' and end '
            elif (cTest == 's'):
                strESEDB = self.dictRecord[strKey]
            elif (cTest == 'i'):
                strESEDB = format(self.dictRecord[strKey], "d")
            elif (cTest == 'b'):
                if (isinstance(self.dictRecord[strKey], bool)):
                    strESEDB = format(self.dictRecord[strKey], "")
                else:  # ..Integer
                    strFmt = "08b"               # ...setup flag format for 8 bit integer
                    if (self.dictRecord[strKey] > 255):
                        strFmt = "016b"          # ...setup flag format for 16 bit integer format
                    if (self.dictRecord[strKey] > 65535):
                        strFmt = "032b"          # ...setup flag format for 32 bit integer format
                    if (self.dictRecord[strKey] > 4294967295):
                        strFmt = "064b"          # ...setup flag format for 64 bit integer format
                    strESEDB = format(self.dictRecord[strKey], strFmt)
            elif (cTest == 'f'):
                strESEDB = format(self.dictRecord[strKey], "G")
            elif (cTest == 'd'):
                strESEDB = utils.getFormattedWinToPyTimeUTC(self.dictRecord[strKey])
        return strESEDB


    def printInfo(self, bHead = True):
        strEnhance = " ESEDB Enhance:"
        # If there is no output...
        if (self.dictRecord == None):
            if bHead:
                print(strEnhance + " None")
            return

        # Otherwise, print...
        if bHead:
            print(strEnhance)
        if (config.ARGS.verbose > 0):
            for strKey in self.iColNames:
                strESEDB = self.getStr(strKey)
                if (strESEDB != None):
                    print("%s%s" % (self.iColNames[strKey][2], strESEDB))
        else:
            strESEDB = self.getStr("TCID")
            print("%s%s" % (self.iColNames["TCID"][2], strESEDB))
        return

    def examineRecord(self, strCmd):
        strValidRecord = "Enter a valid record number"

        print("List Record")
        if (strCmd[2:] == ""):
            print(strValidRecord)
        else:
            # Store and modify verbosity...
            iVerboseOld = config.ARGS.verbose
            if (iVerboseOld < 1):
                config.ARGS.verbose = 1

            try:
                iRec = int(strCmd[2:])
                try:
                    dictRecord = self.listRecords[iRec - 1]
                    print("Record: %d" % iRec)
                    self.printInfo(False)
                    print()
                except:
                    print(strValidRecord)
            except:
                print(strValidRecord)

            # Restore verbosity...
            config.ARGS.verbose = iVerboseOld

        return


    def examine(self):
        import re
        import readline

        funcInput = input

        def prompt(strMessage, strErrorMessage, isValid):
            # Prompt for input given a message and return that value after verifying the input.
            #
            # Keyword arguments:
            #   strMessage -- the message to display when asking the user for the value
            #   strErrorMessage -- the message to display when the value fails validation
            #   isValid -- a function that returns True if the value given by the user is valid

            res = None
            while res is None:
                res = funcInput(str(strMessage)+' > ')
                if (not isValid(res)):
                    print(str(strErrorMessage))
                    res = None
            return res

        strValidColumn = "Enter a valid column number"
        strRecordsFound = "Records Found: %d\n"
        strMessage = "ESEDB Explorer"
        strErrorMessage = "A valid command must be provided. Try 'h'."
        reIsValid = re.compile(r"^[ehlqs]$|^l .+$")
        isValid = lambda v : reIsValid.search(v)
        reIsValidSearch = re.compile(r"^[ehlq]$|^[clv] .*$")
        isValidSearch = lambda v : reIsValidSearch.search(v)
        while (True):
            strCmd = prompt(strMessage,
                            strErrorMessage,
                            isValid)

            if (strCmd == "h"):  # Help
                print("Help")
                print("Available Commands:")
                print("  h - this help")
                print("  l - list all stored ESEDB data")
                print("  l record - list the specified ESEDB record verbose")
                print("  s - search stored ESEDB data")
                print("  e - exit (quit) ESEDB Explorer")
                print("  q - exit (quit) ESEDB Explorer")

            elif (strCmd == "l"):  # List
                print("List")
                iCount = 0
                for dictRecord in self.listRecords:
                    iCount += 1
                    print("Record: %d" % iCount)
                    self.printInfo(False)
                    print()
                print(strRecordsFound % iCount)

            elif (strCmd[:2] == "l "):  # List Record
                self.examineRecord(strCmd)

            elif (strCmd == "s"):  # Search
                strColKey = None
                iCol = None
                strRegEx = None

                while (True):
                    strSearchMsg = "All Columns" if (strColKey == None) else ("Column %d (%s)" % (iCol, strColKey))
                    strCmd = prompt(strMessage + ": Search " + strSearchMsg,
                                    strErrorMessage,
                                    isValidSearch)

                    if (strCmd == "h"):  # Help
                        print("Help")
                        print("Available Commands:")
                        print("  h - this help")
                        print("  l - list all searchable columns")
                        print("  l record - list the specified ESEDB record verbose")
                        print("  c column - select specified column number (blank for all)")
                        print("  v regex - search for value matching regex in selected column")
                        print("  e - exit (quit) Search")
                        print("  q - exit (quit) Search")

                    elif (strCmd == "l"):  # List
                        print("List")
                        for strKey in self.iCol:
                            print("% 4d : %6s  %s" % (self.iCol[strKey], strKey, self.iColNames[strKey][0]))

                    elif (strCmd[:2] == "l "):  # List Record
                        self.examineRecord(strCmd)

                    elif (strCmd[:2] == "c "):  # Column Selection
                        print("Column Selection")
                        if (strCmd[2:] == ""):
                            strColKey = None
                            iCol = None
                        else:
                            try:
                                iColNew = int(strCmd[2:])
                                try:
                                    strColKey = list(self.iCol.keys())[list(self.iCol.values()).index(iColNew)]
                                    iCol = iColNew
                                except:
                                    print("Enter a valid column number")
                            except:
                                print("Enter a valid column number")

                    elif (strCmd[:2] == "v "):  # Value RegEx
                        print("Searching columns in records...")
                        iCount = 0
                        if (strCmd[2:] == ""):
                            strRegEx = None
                        else:
                            strRegEx = strCmd[2:]
                            reObj = re.compile(strRegEx)
                            isFound = lambda v : reObj.search(v) if (v != None) else False
                            iRec = 0
                            for dictRecord in self.listRecords:
                                iRec += 1
                                bFound = False
                                if (strColKey == None):
                                    for strKey in dictRecord:
                                        if isFound(self.getStr(strKey)):
                                            bFound = True
                                            break
                                elif isFound(self.getStr(strColKey)):
                                    bFound = True

                                if (bFound):
                                    iCount += 1
                                    print("Record: %d" % iRec)
                                    self.printInfo(False)
                                    print()
                        print(strRecordsFound % iCount)

                    elif (strCmd == "e" or strCmd == "q"):  # Exit/Quit
                        break

                    else:
                        print(strErrorMessage)

            elif (strCmd == "e" or strCmd == "q"):  # Exit/Quit
                break

            else:
                print(strErrorMessage)

        del readline
        del re
        return


    def search(self, strTCID):
        self.dictRecord = None
        if (self.listRecords == None or strTCID == None):
            return False

        strConvertTCID = strTCID
        if (len(strTCID)%2 == 1):
            strConvertTCID = "0" + strTCID
        try:
            bstrTCID = unhexlify(strConvertTCID)
        except:
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: Cannot unhex given Thumbnail Cache ID (%s) for compare\n" % strConvertTCID)
            return False

        for dictRecord in self.listRecords:
    #        # TEST TCID Compare...
    #        print(str(hexlify(bstrTCID))[2:-1] + " <> " + str(hexlify(dictRecord["BTCID"]))[2:-1])
            if (bstrTCID == dictRecord["TCID"]):
                self.dictRecord = dictRecord
                break

        if (self.dictRecord == None):
            return False

        return True


    def isLoaded(self):
        if (isinstance(self.edbFile, bool)):
            return self.edbFile
        else:  # ...file object...
            return False  # ...in the process of loading
