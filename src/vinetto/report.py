# -*- coding: UTF-8 -*-
"""
module report.py
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumbs.db files
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
file_minor = "4"
file_micro = "4"


from time import time
from os.path import dirname, basename, abspath, getmtime

import vinetto.config as config

from vinetto.utils import TN_CATALOG, TN_STREAMS, \
                          getCatalogEntry, convertToPyTime, getFormattedTimeUTC
from pkg_resources import resource_filename


HTTP_HEADER  = []
HTTP_TYPE    = []
HTTP_PIC_ROW = []
HTTP_ORPHANS = []
HTTP_FOOTER  = []

IMGTAG = "<IMG SRC=\"__TNFNAME__\" ALT=\"__TNNAME__\" style=\"background-color:black;\" />"


class Report:
    """ Vinetto report SuperClass.  """
    def __init__(self, target, outputdir, verstr, fileType, fileSize, md5):
        """ Initialize a new Report instance.  """
        self.tDBfname   = basename(target)
        self.tDBdirname = abspath(dirname(target))
        self.tDBmtime   = getmtime(target)
        self.outputdir  = outputdir
        self.verstr     = verstr
        self.fileType   = fileType
        self.fileSize   = fileSize
        self.md5        = md5


class HttpReport(Report):
    """ Html vinetto elementary mode report Class.  """
    def __init__(self, charset, tDBfname, outputdir, verstr, fileType, fileSize, md5):
        """ Initialize a new HtttReport instance.  """
        Report.__init__(self, tDBfname, outputdir, verstr, fileType, fileSize, md5)
        self.rownumber = 0
        separatorID = 0

        # Load HTTP sections...
        for strLine in open(resource_filename('vinetto', 'data/HtRepTemplate.html'), "r").readlines():
            if strLine.find("__CHARSET__") > 0:
                strLine = strLine.replace("__CHARSET__", charset)
            if strLine.find("__ITS__") >= 0:
                separatorID += 1
                continue

            if (separatorID == 0):
                HTTP_HEADER.append(strLine)
            elif (separatorID == 1 and self.fileType == config.THUMBS_TYPE_OLE):
                HTTP_TYPE.append(strLine)
            elif (separatorID == 2 and self.fileType == config.THUMBS_TYPE_CMMM):
                HTTP_TYPE.append(strLine)
            elif (separatorID == 3 and self.fileType == config.THUMBS_TYPE_IMMM):
                HTTP_TYPE.append(strLine)
            elif (separatorID == 4):
                HTTP_PIC_ROW.append(strLine)
            elif (separatorID == 5):
                HTTP_ORPHANS.append(strLine)
            elif (separatorID == 6):
                HTTP_FOOTER.append(strLine)

        self.TNidList   = []
        self.TNtsList   = []
        self.TNnameList = []


    def setOLE(self, oleBlock):
        # Initialize Type 1 report (OLE, Thumbs.db) for report type section
        self.tDBREcolor = oleBlock["color"]
        self.tDBREpdid  = oleBlock["PDID"]
        self.tDBREndid  = oleBlock["NDID"]
        self.tDBREsdid  = oleBlock["SDID"]
        self.tDBREcid   = oleBlock["CID"]
        self.tDBREuserflags = oleBlock["userflags"]
        self.tDBREctime = getFormattedTimeUTC( convertToPyTime(oleBlock["create"]) )
        self.tDBREmtime = getFormattedTimeUTC( convertToPyTime(oleBlock["modify"]) )
        self.tDBREsid_firstSecDir = oleBlock["SID_firstSecDir"]
        self.tDBREsid_sizeDir = oleBlock["SID_sizeDir"]


    def setCMMM(self, strFormatType, strCacheType, tDB_cacheOff1st, tDB_cacheOff1stAvail,
                 tDB_cacheCount):
        # Initialize Type 2 report (CMMM, Thumbcache_*) for report type section
        self.tDBREformatType = strFormatType
        self.tDBREcacheType = strCacheType
        self.tDBREcacheOff1st = tDB_cacheOff1st
        self.tDBREcacheOff1stAvail = tDB_cacheOff1stAvail
        self.tDBREcacheCount = tDB_cacheCount


    def setType3(self, strFormatType, tDB_entryUsed, tDB_entryCount):
        # Initialize Type 3 report (IMMM, Thumbcache_*) for report type section
        self.tDBREformatType = strFormatType
        self.tDBREentryUsed = tDB_entryUsed
        self.tDBREentryCount = tDB_entryCount


    def headwrite(self):
        # Write report header...
        self.repfile = open(self.outputdir + self.tDBfname + ".html", "w")
        for strLine in HTTP_HEADER:
            strLine = strLine.replace("__DATEREPORT__",  "Report Date: " + getFormattedTimeUTC( time() ))
            strLine = strLine.replace("__TDBDIRNAME__",  self.tDBdirname)
            strLine = strLine.replace("__TDBFNAME__",    self.tDBfname)
            strLine = strLine.replace("__TDBMTIME__",    getFormattedTimeUTC(self.tDBmtime))
            strLine = strLine.replace("__FILETYPE__",    config.THUMBS_FILE_TYPES[self.fileType])
            strLine = strLine.replace("__FILESIZE__",    str(self.fileSize))
            strLine = strLine.replace("__MD5__",         self.md5 if not None else "Not Calculated")

            self.repfile.write(strLine)


    def typewrite(self):
        # Write report type...
        for strLine in HTTP_TYPE:
            # Adjust Type 1 (OLE, Thumbs.db)...
            if (self.fileType == config.THUMBS_TYPE_OLE):
                strLine = strLine.replace("__TDBRECOLOR__",  "%d (%s)" % (self.tDBREcolor, "Black" if self.tDBREcolor else "Red"))
                strLine = strLine.replace("__TDBREPDID__",   ("None" if (self.tDBREpdid == config.OLE_NONE_BLOCK) else str(self.tDBREpdid)))
                strLine = strLine.replace("__TDBRENDID__",   ("None" if (self.tDBREndid == config.OLE_NONE_BLOCK) else str(self.tDBREndid)))
                strLine = strLine.replace("__TDBRESDID__",   ("None" if (self.tDBREsdid == config.OLE_NONE_BLOCK) else str(self.tDBREsdid)))
                strLine = strLine.replace("__TDBRECLASS__",  self.tDBREcid)
                strLine = strLine.replace("__TDBREUFLAGS__", self.tDBREuserflags)
                strLine = strLine.replace("__TDBRECTIME__",  self.tDBREctime)
                strLine = strLine.replace("__TDBREMTIME__",  self.tDBREmtime)
                strLine = strLine.replace("__TDBRESID1SD__", str(self.tDBREsid_firstSecDir))
                strLine = strLine.replace("__TDBRESIDSZD__", str(self.tDBREsid_sizeDir))

            # Adjust Type 2 (CMMM, Thumbcache_*)...
            elif (self.fileType == config.THUMBS_TYPE_CMMM):
                strLine = strLine.replace("__TDBREFORMATTYPE__",       self.tDBREformatType)
                strLine = strLine.replace("__TDBRECACHETYPE__",        self.tDBREcacheType)
                strLine = strLine.replace("__TDBRECACHEOFF1ST__",      str(self.tDBREcacheOff1st))
                strLine = strLine.replace("__TDBRECACHEOFF1STAVAIL__", str(self.tDBREcacheOff1stAvail))
                strLine = strLine.replace("__TDBRECACHECOUNT__",       str(self.tDBREcacheCount))

            # Adjust Type 3 (IMMM, Thumbcache_*)...
            elif (self.fileType == config.THUMBS_TYPE_IMMM):
                strLine = strLine.replace("__TDBREFORMATTYPE__", self.tDBREformatType)
                strLine = strLine.replace("__TDBREENTRYUSED__",  str(self.tDBREentryUsed))
                strLine = strLine.replace("__TDBREENTRYCOUNT__", str(self.tDBREentryCount))

            self.repfile.write(strLine)


    def close(self, strStats):
        # Write report footer...
        for strLine in HTTP_FOOTER:
            strLine = strLine.replace("__TYPESTATS__", strStats)
            strLine = strLine.replace("__VERSION__", "Vinetto " + self.verstr)

            self.repfile.write(strLine)

        self.repfile.close()


    def rowFlush(self):
        # Process a report line...
        self.rownumber += 1
        for strLine in HTTP_PIC_ROW:
            strLine = strLine.replace("__ROWNUMBER__", str(self.rownumber))
            # Fill...
            for j in range(len(self.tnId)):
                strLine = strLine.replace("__TNFILLED__" + str(j), "1")
                buff = IMGTAG.replace("__TNFNAME__", self.tnFname[j])
                buff = buff.replace("__TNNAME__", (self.tnName[j] if (self.tnName[j] != "") else self.tnId[j]))
                strLine = strLine.replace("__IMGTAG__" + str(j), buff)
                #strLine = strLine.replace("__TNID__" + str(j), self.tnId[j])
                strLine = strLine.replace("__TNID__" + str(j), self.tnFname[j])
            # Blank...
            for j in range(len(self.tnId), 7):
                strLine = strLine.replace("__TNFILLED__" + str(j), "0")
                strLine = strLine.replace("__IMGTAG__" + str(j), " ")
                strLine = strLine.replace("__TNID__" + str(j), " ")

            self.repfile.write(strLine)

        self.repfile.write("<TABLE WIDTH=\"720\">" +
                           "<TR><TD><P ALIGN=\"LEFT\">\n")
        strEntryNotFound = "** %s entry not found **" % ("Catalog" if self.fileType == config.THUMBS_TYPE_OLE else "Cache ID")
        for i in range(len(self.tnId)):
            if (self.tnName[i] != ""):
                self.repfile.write("<TT>" +
                                   self.tnId[i].replace(" ", "&nbsp;") + ": " +
                                   self.tnTs[i].replace(" ", "&nbsp;") + " &nbsp;" +
                                   self.tnName[i].replace(" ", "&nbsp;") +
                                   "</TT><br />\n")
            else:
                self.repfile.write("<TT STYLE=\"color: blue\">" +
                                   self.tnId[i].replace(" ", "&nbsp;") + ": " +
                                   strEntryNotFound +
                                   "</TT><br />\n")

        self.repfile.write("</P></TD></TR></TABLE>")

        self.tnId    = []
        self.tnFname = []
        self.tnTs    = []
        self.tnName  = []


    def printOrphanCatEnt(self, OrphanICat):
        # Print orphan catalog entry...
        if (OrphanICat != []):
            for strLine in HTTP_ORPHANS:
                if strLine.find("__ORPHANENTRY__") < 0:
                    self.repfile.write(strLine)
                else:
                    for iCatEntryID in OrphanICat:
                        catEntry = getCatalogEntry(iCatEntryID)
                        for (strTimeStamp, strEntryName) in catEntry:
                            strTT = str("<TT>" +
                                        ("% 4d" % iCatEntryID).replace(" ", "&nbsp;") + ": " +
                                        strTimeStamp.replace(" ", "&nbsp;") + " &nbsp;" +
                                        strEntryName.replace(" ", "&nbsp;") +
                                        "</TT><br />\n")
                            orphanLine = strLine.replace("__ORPHANENTRY__", strTT)
                            self.repfile.write(orphanLine)


    def populateCell(self, key, strFilePath, strTimeStamp, strEntryName):
        # Organize the data for a cell in a report line...
        bFlush = False
        if (type(key) == int):
            self.tnId.append("% 4i" % key)
        else:
            self.tnId.append(key)
            bFlush = True
        self.tnFname.append(strFilePath)
        self.tnTs.append(strTimeStamp)
        self.tnName.append(strEntryName)
        if (bFlush or len(self.tnId) >= 7):
            self.rowFlush()

    def flush(self, astrStats, strSubDir):
        self.headwrite()
        self.typewrite()

        # Process the report body and the report end...
        self.rownumber = 0
        self.tnId    = []
        self.tnFname = []
        self.tnTs    = []
        self.tnName  = []

        for key in TN_STREAMS:
            for (iType, strFileName, bStreamID) in TN_STREAMS[key][1]:
                if (bStreamID):
                    strFilePath = strSubDir + "/" + strFileName + "." + TN_STREAMS[key][0]
                else:
                    strFilePath = "./" + strFileName + "." + TN_STREAMS[key][0]
                catEntry = getCatalogEntry(key)
                if (len(catEntry) == 0):
                    self.populateCell(key, strFilePath, "", "")
                else:
                    for (strTimeStamp, strEntryName) in catEntry:
                        self.populateCell(key, strFilePath, strTimeStamp, strEntryName)

        if (len(self.tnId) > 0):
            self.rowFlush()

        # Scanning for orphan catalog entries
        OrphanICat = []
        for iCatEntryID in TN_CATALOG:
            if iCatEntryID not in TN_STREAMS:
                OrphanICat.append(iCatEntryID)
        self.printOrphanCatEnt(OrphanICat)

        strStats = ""
        if (astrStats != None):
            for strStat in astrStats:
                strStats += strStat.replace(" ", "&nbsp;") + "<br />"
            self.close(strStats[:-6])
        else:
            strStats += "No Stats!".replace(" ", "&nbsp;")
            self.close(strStats)