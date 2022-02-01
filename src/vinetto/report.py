# -*- coding: UTF-8 -*-
"""
module report.py
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
file_minor = "4"
file_micro = "10"


from time import time
from os.path import dirname, basename, abspath, getmtime
from pkg_resources import resource_filename

import vinetto.version as version
import vinetto.config as config
import vinetto.error as verror
import vinetto.utils as utils


HTTP_HEADER  = []
HTTP_TYPE    = []
HTTP_PIC_ROW = []
HTTP_ORPHANS = []
HTTP_FOOTER  = []

IMGTAG = "<img src=\"__TNIMAGE__\" alt=\"__TNALT__\" />"

IMGCOLS = 7


###############################################################################
# Vinetto Report SuperClass
###############################################################################
class Report:
    def __init__(self, strCharSet, strOutputDir, dictHead):
        """ Initialize a new Report instance.  """
        self.strCharSet = strCharSet

        self.strOutputDir = strOutputDir

        self.dictHead = dictHead
        self.dictHead["Filename"] = basename(dictHead["FilePath"])
        self.dictHead["Path"] = abspath(dictHead["FilePath"])
        self.dictHead["ModifyTime"] = getmtime(dictHead["FilePath"])

        self.dictMeta = {}

        self.iStreamCount = 0
        self.iFileCount = 0
        self.iIDCount = 0

###############################################################################
# Vinetto HTML Report (elementary mode) Class
###############################################################################
class HtmlReport(Report):
    def __init__(self, strCharSet, strOutputDir, dictHead):
        # Initialize a new HtmlReport instance...
        Report.__init__(self, strCharSet, strOutputDir, dictHead)
        self.iRow = 0

        # Load HTTP sections...
        iSeparatorID = 0
        for strLine in open(resource_filename('vinetto', 'data/HtmlReportTemplate.html'), "r").readlines():
            if strLine.find("__ITS__") >= 0:
                iSeparatorID += 1
                continue

            if (iSeparatorID == 0):
                HTTP_HEADER.append(strLine)
            elif (iSeparatorID == 1 and self.dictHead["FileType"] == config.THUMBS_TYPE_OLE):
                HTTP_TYPE.append(strLine)
            elif (iSeparatorID == 2 and self.dictHead["FileType"] == config.THUMBS_TYPE_CMMM):
                HTTP_TYPE.append(strLine)
            elif (iSeparatorID == 3 and self.dictHead["FileType"] == config.THUMBS_TYPE_IMMM):
                HTTP_TYPE.append(strLine)
            elif (iSeparatorID == 4):
                HTTP_PIC_ROW.append(strLine)
            elif (iSeparatorID == 5):
                HTTP_ORPHANS.append(strLine)
            elif (iSeparatorID == 6):
                HTTP_FOOTER.append(strLine)

        self.listIDs        = []
        self.listFileNames  = []
        self.listTimestamps = []
        self.listEntryNames = []


    #--------------------------------------------------------------------------
    # Public Methods
    #--------------------------------------------------------------------------

    def setOLE(self, dictOLEMeta):
        if (dictOLEMeta == None or not isinstance(dictOLEMeta, dict)):
            return
        # Initialize Type 1 report (OLE, Thumbs.db) for report type section
        self.dictMeta = dictOLEMeta


    def setCMMM(self, dictCMMMMeta):
        if (dictCMMMMeta == None or not isinstance(dictCMMMMeta, dict)):
            return
        # Initialize Type 2 report (CMMM, Thumbcache_*) for report type section
        self.dictMeta = dictCMMMMeta


    def setIMMM(self, dictIMMMMeta):
        if (dictIMMMMeta == None or not isinstance(dictIMMMMeta, dict)):
            return
        # Initialize Type 3 report (IMMM, Thumbcache_*) for report type section
        self.dictMeta = dictIMMMMeta


    def flush(self, astrStats, strSubDir, tdbStreams = None, tdbCatalog = None):
        self.__writeHead()  # ...opens HTML file for write

        self.__writeMeta()

        # Process the report body and the report end...
        self.iRow = 0
        self.listIDs        = []
        self.listFileNames  = []
        self.listTimestamps = []
        self.listEntryNames = []

        if (tdbStreams != None and len(tdbStreams) > 0):
            for key in tdbStreams:
                self.iStreamCount += 1
                bStreamID = tdbStreams[key][1]
                for strFileName in tdbStreams[key][2]:
                    self.iFileCount += 1
                    if (bStreamID):
                        strFilePath = strSubDir
                    else:
                        strFilePath = "."
                    strFilePath += "/" + strFileName + "." + tdbStreams[key][0][0]

                    if (tdbCatalog == None or len(tdbCatalog) == 0 or not key in tdbCatalog):
                        self.__populateCell(key, strFilePath)
                    else:
                        self.__populateCell(key, strFilePath, tdbCatalog[key])
                        self.iIDCount += 1

        if (len(self.listIDs) > 0):
            self.__rowFlush()

        self.__printOrphanCatEnt(tdbStreams, tdbCatalog)

        strCounts = ""
        if (self.iStreamCount > 0):
            strCounts = (("Entries: " + str(self.iStreamCount)).replace(" ", "&nbsp;") + "<br />" +
                         ("  Files: " + str(self.iFileCount)).replace(" ", "&nbsp;")+ "<br />" +
                         ("  TCIDs: " + str(self.iIDCount)).replace(" ", "&nbsp;"))
        else:
            strCounts += "No Counts!".replace(" ", "&nbsp;")

        strStats = ""
        if (astrStats != None):
            for strStat in astrStats:
                strStats += strStat.replace(" ", "&nbsp;") + "<br />"
            strStats = strStats[:-6]
        else:
            strStats += "No Stats!".replace(" ", "&nbsp;")

        self.__close(strCounts, strStats)


    #--------------------------------------------------------------------------
    # Private Methods
    #--------------------------------------------------------------------------

    def __writeHead(self):
        # Write report header...
        strFileName = self.strOutputDir + self.dictHead["Filename"] + ".html"
        try:
            self.repfile = open(strFileName, "w")
        except:
            raise verror.ReportError(" Error (Report): Cannot create " + strFileName)
        for strLine in HTTP_HEADER:
            strLine = strLine.replace("__CHARSET__",    self.strCharSet)
            strLine = strLine.replace("__DATEREPORT__", "Report Date: " + utils.getFormattedTimeUTC( time() ))
            strLine = strLine.replace("__TDBDIRNAME__", self.dictHead["Path"])
            strLine = strLine.replace("__TDBFNAME__",   self.dictHead["Filename"])
            strLine = strLine.replace("__TDBMTIME__",   utils.getFormattedTimeUTC(self.dictHead["ModifyTime"]))
            strLine = strLine.replace("__FILETYPE__",   config.THUMBS_FILE_TYPES[self.dictHead["FileType"]])
            strLine = strLine.replace("__FILESIZE__",   str(self.dictHead["FileSize"]))
            strLine = strLine.replace("__MD5__",        self.dictHead["MD5"] if (self.dictHead["MD5"] != None) else "Not Calculated")

            self.repfile.write(strLine)


    def __writeMeta(self):
        # Write report type...
        for strLine in HTTP_TYPE:
            # Adjust Type 1 (OLE, Thumbs.db)...
            if (self.dictHead["FileType"] == config.THUMBS_TYPE_OLE):
                strLine = strLine.replace("__TDBRECOLOR__",  "%d (%s)" % (self.dictMeta["color"], "Black" if self.dictMeta["color"] else "Red"))
                strLine = strLine.replace("__TDBREPDID__",   ("None" if (self.dictMeta["PDID"] == config.OLE_NONE_BLOCK) else str(self.dictMeta["PDID"])))
                strLine = strLine.replace("__TDBRENDID__",   ("None" if (self.dictMeta["NDID"] == config.OLE_NONE_BLOCK) else str(self.dictMeta["NDID"])))
                strLine = strLine.replace("__TDBRESDID__",   ("None" if (self.dictMeta["SDID"] == config.OLE_NONE_BLOCK) else str(self.dictMeta["SDID"])))
                strLine = strLine.replace("__TDBRECLASS__",  self.dictMeta["CID"])
                strLine = strLine.replace("__TDBREUFLAGS__", self.dictMeta["userflags"])
                strLine = strLine.replace("__TDBRECTIME__",  utils.getFormattedWinToPyTimeUTC(self.dictMeta["create"]))
                strLine = strLine.replace("__TDBREMTIME__",  utils.getFormattedWinToPyTimeUTC(self.dictMeta["modify"]))
                strLine = strLine.replace("__TDBRESID1SD__", str(self.dictMeta["SID_firstSecDir"]))
                strLine = strLine.replace("__TDBRESIDSZD__", str(self.dictMeta["SID_sizeDir"]))

            # Adjust Type 2 (CMMM, Thumbcache_*)...
            elif (self.dictHead["FileType"] == config.THUMBS_TYPE_CMMM):
                strLine = strLine.replace("__TDBREFORMATTYPE__",       self.dictMeta["FormatTypeStr"])
                strLine = strLine.replace("__TDBRECACHETYPE__",        self.dictMeta["CacheTypeStr"])
                strLine = strLine.replace("__TDBRECACHEOFF1ST__",      str(self.dictMeta["CacheOff1st"]))
                strLine = strLine.replace("__TDBRECACHEOFF1STAVAIL__", str(self.dictMeta["CacheOff1stAvail"]))
                strLine = strLine.replace("__TDBRECACHECOUNT__",       str(self.dictMeta["CacheCount"]))

            # Adjust Type 3 (IMMM, Thumbcache_*)...
            elif (self.dictHead["FileType"] == config.THUMBS_TYPE_IMMM):
                strLine = strLine.replace("__TDBREFORMATTYPE__", self.dictMeta["FormatTypeStr"])
                strLine = strLine.replace("__TDBREENTRYUSED__",  str(self.dictMeta["EntryUsed"]))
                strLine = strLine.replace("__TDBREENTRYCOUNT__", str(self.dictMeta["EntryCount"]))

            self.repfile.write(strLine)


    def __rowFlush(self):
        # Calculate Catalog Table to augment Row Images...
        strCatalogTable = ""
        if (len(self.listIDs) > 0):
    #        self.repfile.write("<TABLE WIDTH=\"800\">" +
            strCatalogTable = ("<tr><td class=\"title\">Catalog:</td>\n"
                               "<td colspan=\"" + str(IMGCOLS - 1) + "\" style=\"border-top: 6px solid; border-color: transparent;\">\n")
            strEntryNotFound = "** %s entry not found **" % ("Catalog" if self.dictHead["FileType"] == config.THUMBS_TYPE_OLE else "Cache ID")
            for i in range(len(self.listIDs)):
                strCatalogTable += ("<p class=\"tt\">" +
                                    self.listIDs[i].replace(" ", "&nbsp;") + ":&nbsp;")
                if (self.listEntryNames[i] != ""):
                    strCatalogTable += (self.listTimestamps[i].replace(" ", "&nbsp;") + " &nbsp;" +
                                        self.listEntryNames[i].replace(" ", "&nbsp;"))
                else:
                    strCatalogTable += strEntryNotFound
                strCatalogTable += "</p>\n"
            strCatalogTable += "</td></tr>\n"

        # Process a report line...
        self.iRow += 1
        for strLine in HTTP_PIC_ROW:
            # Row Number...
            strLine = strLine.replace("__ROWNUMBER__", str(self.iRow) + ":")
            # Fill cells in row...
            for i in range(len(self.listIDs)):
                # Cell Image Info...
                strImage = IMGTAG.replace("__TNIMAGE__", self.listFileNames[i]).replace(
                                          "__TNALT__", (self.listEntryNames[i] if (self.listEntryNames[i] != "") else self.listIDs[i]))
                strLine = strLine.replace("__IMGTAG__"  + str(i), strImage)
                # ...related to Catalog Entries...
                strLine = strLine.replace("__TNID__"    + str(i), self.listIDs[i])
                # ...related to File Entries...
                strLine = strLine.replace("__TNFNAME__" + str(i), basename(self.listFileNames[i]))
            # Any empty cells in row...
            for i in range(len(self.listIDs), IMGCOLS):
                strLine = strLine.replace("__IMGTAG__"  + str(i), "")
                strLine = strLine.replace( "__TNID__"   + str(i), "")
                strLine = strLine.replace("__TNFNAME__" + str(i), "")

            # Add Catalog Table...
            strLine = strLine.replace("__CATALOGTABLE__", strCatalogTable)

            self.repfile.write(strLine)

        self.listIDs        = []
        self.listFileNames  = []
        self.listTimestamps = []
        self.listEntryNames = []


    def __populateCell(self, key, strFilePath, listCat = [("", "")]):
        for (strTimeStamp, strEntryName) in listCat:
            # Organize the data for a cell in a report line...
            #bFlush = False
            if isinstance(key, int):
                self.listIDs.append("% 4i" % key)
            else:
                self.listIDs.append(key)
                #bFlush = True
            self.listFileNames.append(strFilePath)
            self.listTimestamps.append(strTimeStamp)
            self.listEntryNames.append(strEntryName)
            #if (bFlush or len(self.listIDs) >= IMGCOLS):
            if (len(self.listIDs) >= IMGCOLS):
                self.__rowFlush()

    def __printOrphanCatEnt(self, tdbStreams, tdbCatalog):
        if (tdbStreams == None or len(tdbStreams) == 0 or tdbCatalog == None or len(tdbCatalog) == 0):
            return

        # Scan for orphan catalog entries...
        listOrphans = []
        listOrphanCatIDs = tdbCatalog.getOrphans(tdbStreams)

        # Gather orphan catalog entries...
        for key in listOrphanCatIDs:
            listCat = tdbCatalog[key]
            for (strTimeStamp, strEntryName) in listCat:
                strKey = ("% 4d" % key) if isinstance(key, int) else key
                listOrphans.append(strKey.replace(" ", "&nbsp;") + ": " +
                                   strTimeStamp.replace(" ", "&nbsp;") + " &nbsp;" +
                                   strEntryName.replace(" ", "&nbsp;") + "\n")
        if (len(listOrphans) == 0):
            return

        # Print orphan catalog entries...
        for strLine in HTTP_ORPHANS:
            if "__TNORPHAN__" not in strLine:
                self.repfile.write(strLine)
            else:
                # Reuse this __TNORPHAN__ strLine to populate rows...
                for strOrphan in listOrphans:
                    strOrphanLine = strLine.replace("__TNORPHAN__", strOrphan)
                    self.repfile.write(strOrphanLine)


    def __close(self, strCounts, strStats):
        # Write report footer...
        for strLine in HTTP_FOOTER:
            strLine = strLine.replace("__COUNTSTATS__", strCounts)
            strLine = strLine.replace("__TYPESTATS__", strStats)
            strLine = strLine.replace("__VERSION__", "Vinetto " + version.STR_VERSION)

            self.repfile.write(strLine)

        self.repfile.close()


