# -*- coding: UTF-8 -*-
"""
module esedb.py
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


import sys
from struct import unpack
from binascii import hexlify, unhexlify

import vinetto.config as config
import vinetto.error as verror


def prepareESEDB():
    try:
        from vinetto.lib import pyesedb
        bEDBFileGood = True
    except:
        # Hard Error!  The "pyesedb" library is installed locally with Vinetto,
        #   so missing "pyesedb" library is bad!
        raise verror.InstallError(" Error (Install): Cannot import local library pyesedb")

    pyesedb_ver = pyesedb.get_version()
    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info: Imported pyesedb version %s\n" % pyesedb_ver)

    # Open ESEDB file...
    try:
        config.ESEDB_FILE = pyesedb.file()
        config.ESEDB_FILE.open(config.ARGS.edbfile)
    except IOError:
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: Cannot opened ESEDB File for enhanced processing\n")
        return False

    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info: Opened ESEDB file %s\n" % config.ARGS.edbfile)

#    # TEST Get Tables...
#    iTblCnt = config.ESEDB_FILE.get_number_of_tables()
#    sys.stderr.write(" DBG: Got %d tables\n" % iTblCnt)
#    for iTbl in range(iTblCnt):
#        table = config.ESEDB_FILE.get_table(iTbl)
#        if (table == None):
#            sys.stderr.write(" DBG:   Table %d is None\n" % iTbl)
#            continue
#        strTblName = table.get_name()
#        sys.stderr.write(" DBG:   Table %d Name %s\n" % (iTbl, strTblName))

    strSysIndex = "SystemIndex_"
    strTableName = "PropertyStore"
    config.ESEDB_TABLE = config.ESEDB_FILE.get_table_by_name(strSysIndex + strTableName)
    if (config.ESEDB_TABLE == None):  # ...try older table name...
        strTableName = "0A"
        config.ESEDB_TABLE = config.ESEDB_FILE.get_table_by_name(strSysIndex + strTableName)
    if (config.ESEDB_TABLE == None):  # ...still no table available?...
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: Cannot opened ESEDB Table for enhanced processing\n")
        return False

    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info: Opened ESEDB Table %s%s for enhanced processing\n" % (strSysIndex, strTableName))

    iColCnt = config.ESEDB_TABLE.get_number_of_columns()
    if (config.ARGS.verbose > 1):
        sys.stderr.write(" Info:     Got %d columns\n" % iColCnt)
    iColCntFound = 0
    for iCol in range(iColCnt):
        column = config.ESEDB_TABLE.get_column(iCol)
        strColName = column.get_name()
        for strKey in config.ESEDB_ICOL_NAMES:
            if (strColName.endswith(config.ESEDB_ICOL_NAMES[strKey][0])):
                config.ESEDB_ICOL[strKey] = iCol  # ...column number for column name
                iColCntFound += 1

        if (iColCntFound == len(config.ESEDB_ICOL_NAMES)):  # Total Columns searched
            break

    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info:        ESEDB %d columns of %d possible\n" % (iColCntFound, len(config.ESEDB_ICOL_NAMES)))

    return True


def loadESEDB():
    if (config.ESEDB_ICOL["TCID"] == None):
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: No ESEDB Image column %s available\n" % ESEDB_ICOL_NAMES["TCID"][0])
        return False
    if (config.ESEDB_ICOL["MIME"] == None and config.ESEDB_ICOL["CTYPE"] == None and config.ESEDB_ICOL["ITT"] == None):
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: No ESEDB Image columns %s available\n" %
                             (ESEDB_ICOL_NAMES["MIME"][0] + ", " +
                              ESEDB_ICOL_NAMES["CTYPE"][0] + ", or " +
                              ESEDB_ICOL_NAMES["ITT"][0]))
        return False

    config.ESEDB_REC_LIST = []

    iRecCnt = config.ESEDB_TABLE.get_number_of_records()
    strRecIPD = None
    strRecIU = None
    for iRec in range(iRecCnt):
        record = config.ESEDB_TABLE.get_record(iRec)

        # Test for ThumbnailCacheId exists...
        bstrRecTCID = record.get_value_data(config.ESEDB_ICOL["TCID"])
        if (bstrRecTCID == None):
            continue

        # Test for image type record...
        strMime = ""
        if (config.ESEDB_ICOL["MIME"] != None):
            strMime = (record.get_value_data_as_string(config.ESEDB_ICOL["MIME"]) or "")
        strCType = ""
        if (config.ESEDB_ICOL["CTYPE"] != None):
            strCType = (record.get_value_data_as_string(config.ESEDB_ICOL["CTYPE"]) or "")
        strITT = ""
        if (config.ESEDB_ICOL["ITT"] != None):
            strITT = (record.get_value_data_as_string(config.ESEDB_ICOL["ITT"]) or "")
        strImageTest = strMime + strCType + strITT
        if (not "image" in strImageTest):
            continue

#        # TEST Record Retrieval...
#        print("\nTCID: " + str( hexlify( bstrRecTCID ))[2:-1])
#        for strKey in config.ESEDB_ICOL_NAMES:
#            if (strKey == "TCID"):
#                continue
#            sys.stdout.write(strKey + ": ")
#            rawESEDB = processESEDBInfo(record, strKey, True)
#            print(rawESEDB)

        dictRecord = {}
        dictRecord["TCID"]  = bstrRecTCID
        dictRecord["MIME"]  = strMime
        dictRecord["CTYPE"] = strCType
        dictRecord["ITT"]   = strITT

        for strKey in config.ESEDB_ICOL_NAMES:
            if (strKey == "TCID" or strKey == "MIME" or strKey == "CTYPE" or strKey == "ITT"):
                continue
            dictRecord[strKey] = processESEDBInfo(record, strKey, True)

        config.ESEDB_REC_LIST.append(dictRecord)

#    # TEST: Print ESEDB Image Records...
#    for dictRecord in config.ESEDB_REC_LIST:
#        printESEDBInfo(dictRecord, False)
#        print()

    if (len(config.ESEDB_REC_LIST) == 0):
        config.ESEDB_REC_LIST = None
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: No ESEDB Image data available\n")
        return False

    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info:        ESEDB Image data loaded\n")

    return True


def processESEDBInfo(recordESEDB, strKey, bRaw = False):
    strESEDB = None
    rawESEDB = None
    dataESEDB = None
    iCol = config.ESEDB_ICOL[strKey]
    if (iCol != None):
        cTest = config.ESEDB_ICOL_NAMES[strKey][1]
        # Format the key's value for output...
        # 'x' - bstr  == (Large) Binary Data
        # 's' - str   == (Large) Text
        # 'i' - int   == Integer (32/16/8)-bit (un)signed
        # 'b' - bool  == Boolean or Boolean Flags (Integer)
        # 'f' - float == Floating Point (Double Precision) (64/32-bit)
        # 'd' - date  == Binary Data converted to Formatted UTC Time
        if not bRaw:
            dataESEDB = recordESEDB[strKey]

        if   (cTest == 'x'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data(iCol)
            else:
                strESEDB = str( hexlify( dataESEDB ))[2:-1]  # ...stript off start b' and end '
        elif (cTest == 's'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data_as_string(iCol)
            else:
                strESEDB = dataESEDB
        elif (cTest == 'i'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data_as_integer(iCol)
            else:
                strESEDB = format(dataESEDB, "d")
        elif (cTest == 'b'):
            if bRaw:
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
            else:
                if (isinstance(dataESEDB, bool)):
                    strESEDB = format(dataESEDB, "")
                else:  # ..Integer
                    strFmt = "08b"               # ...setup flag format for 8 bit integer
                    if (dataESEDB > 255):
                        strFmt = "016b"          # ...setup flag format for 16 bit integer format
                    if (dataESEDB > 65535):
                        strFmt = "032b"          # ...setup flag format for 32 bit integer format
                    if (dataESEDB > 4294967295):
                        strFmt = "064b"          # ...setup flag format for 64 bit integer format
                    strESEDB = format(dataESEDB, strFmt)
        elif (cTest == 'f'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data_as_floating_point(iCol)
            else:
                strESEDB = format(dataESEDB, "G")
        elif (cTest == 'd'):
            if bRaw:
                rawESEDB = unpack("<Q", recordESEDB.get_value_data(iCol))[0]
            else:
                strESEDB = getFormattedWinToPyTimeUTC(dataESEDB)
    if bRaw:
        return rawESEDB
    else:
        return strESEDB


def printESEDBInfo(dictESEDB, bHead = True):
    strEnhance = " ESEDB Enhance:"
    # If there is no output...
    if (config.ESEDB_FILE == None or dictESEDB == None):
        if bHead:
            print(strEnhance + " None")
        return

    # Otherwise, print...
    if bHead:
        print(strEnhance)
    if (config.ARGS.verbose > 0):
        for strKey in config.ESEDB_ICOL_NAMES:
            strESEDB = processESEDBInfo(dictESEDB, strKey)
            if (strESEDB != None):
                print("%s%s" % (config.ESEDB_ICOL_NAMES[strKey][2], strESEDB))
    else:
        strESEDB = processESEDBInfo(dictESEDB, "TCID")
        print("%s%s" % (config.ESEDB_ICOL_NAMES["TCID"][2], strESEDB))
    return

def examineESEDBRecord(strCmd):
    strValidRecord = "Enter a valid record number"

    print("List Record")
    if (strCmd[2:] == ""):
        print(strValidRecord)
    else:
        iVerboseOld = config.ARGS.verbose
        config.ARGS.verbose = 1

        try:
            iRec = int(strCmd[2:])
            try:
                dictRecord = config.ESEDB_REC_LIST[iRec - 1]
                print("Record: %d" % iRec)
                printESEDBInfo(dictRecord, False)
                print()
            except:
                print(strValidRecord)
        except:
            print(strValidRecord)

        config.ARGS.verbose = iVerboseOld

    return


def examineESEDB():
    import re
    import readline

    try:
        funcInput = raw_input
    except NameError:
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
    while (True):
        strCmd = prompt(
            strMessage,
            strErrorMessage,
            isValid = lambda v : re.search(r"^[ehlqs]$|^l .+$", v))

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
            for dictRecord in config.ESEDB_REC_LIST:
                iCount += 1
                print("Record: %d" % iCount)
                printESEDBInfo(dictRecord, False)
                print()
            print(strRecordsFound % iCount)

        elif (strCmd[:2] == "l "):  # List Record
            examineESEDBRecord(strCmd)

        elif (strCmd == "s"):  # Search
            strColKey = None
            iCol = None
            strRegEx = None

            while (True):
                strCmd = prompt(
                    (strMessage + ": Search " + ( "All Columns" if (strColKey == None) else ("Column %d (%s)" % (iCol, strColKey)) )),
                    strErrorMessage,
                    isValid = lambda v : re.search(r"^[ehlq]$|^[clv] .*$", v))

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
                    for strKey in config.ESEDB_ICOL:
                        print("% 4d : %6s  %s" % (config.ESEDB_ICOL[strKey], strKey, config.ESEDB_ICOL_NAMES[strKey][0]))

                elif (strCmd[:2] == "l "):  # List Record
                    examineESEDBRecord(strCmd)

                elif (strCmd[:2] == "c "):  # Column Selection
                    print("Column Selection")
                    if (strCmd[2:] == ""):
                        strColKey = None
                        iCol = None
                    else:
                        try:
                            iColNew = int(strCmd[2:])
                            try:
                                strColKey = list(config.ESEDB_ICOL.keys())[list(config.ESEDB_ICOL.values()).index(iColNew)]
                                iCol = iColNew
                            except:
                                print("Enter a valid column number")
                        except:
                            print("Enter a valid column number")

                elif (strCmd[:2] == "v "):  # Value RegEx
                    print("Searching columns in records...")
                    iCount = 0
                    iRec = 0
                    if (strCmd[2:] == ""):
                        strRegEx = None
                    else:
                        strRegEx = strCmd[2:]
                        reObj = re.compile(strRegEx)
                        isFound = lambda v : reObj.search(v) if (v != None) else False
                        for dictRecord in config.ESEDB_REC_LIST:
                            iRec += 1
                            bFound = False
                            if (strColKey == None):
                                for strKey in dictRecord:
                                    if isFound(processESEDBInfo(dictRecord, strKey)):
                                        bFound = True
                                        break
                            elif isFound(processESEDBInfo(dictRecord, strColKey)):
                                bFound = True

                            if (bFound):
                                iCount += 1
                                print("Record: %d" % iRec)
                                printESEDBInfo(dictRecord)
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


def searchESEDB(strTCID):
    if (config.ESEDB_REC_LIST == None or strTCID == None):
        return None

    strConvertTCID = strTCID
    if (len(strTCID)%2 == 1):
        strConvertTCID = "0" + strTCID
    try:
        bstrTCID = unhexlify(strConvertTCID)
    except:
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: Cannot unhex given Thumbnail Cache ID (%s) for compare\n" % strConvertTCID)
        return None

    bFound = False
    for dictRecord in config.ESEDB_REC_LIST:
#        # TEST TCID Compare...
#        print(str(hexlify(bstrTCID))[2:-1] + " <> " + str(hexlify(dictRecord["BTCID"]))[2:-1])
        if (bstrTCID == dictRecord["TCID"]):
            bFound = True
            break

    if (not bFound):
        return None

    return dictRecord


