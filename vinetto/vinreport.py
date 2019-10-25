# -*- coding: UTF-8 -*-
"""
module vinreport.py
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
__minor__ = "4"
__micro__ = "0"
__maintainer__ = "Keven L. Ates"
__author__ = "Michel Roukine"
__location__ = "https://github.com/AtesComp/Vinetto"

HtHeader = []
HtPicRow = []
HtOrphans = []
HtFooter = []
IMGTAG = "<IMG SRC=\"./__TNFNAME__.jpg\" ALT=\"__TNNAME__\">"

from time import time, ctime
from os.path import dirname, basename, abspath, getmtime
from vinetto.vinutils import getCatEntry, TNStreams, Catalog
from pkg_resources import resource_filename

try:
    # Python < 3
    unicode('')
except NameError:
    # Python >= 3
    unicode = str


class Report:
    """ Vinetto report SuperClass.  """
    def __init__ (self, target, outputdir, verstr):
        """ Initialize a new Report instance.  """
        self.tDBfname = basename(target)
        self.tDBdirname = abspath(dirname(target))
        self.tDBmtime = getmtime(target)
        self.outputdir = outputdir
        self.verstr = verstr


class HtRep(Report):
    """ Html vinetto elementary mode report Class.  """
    def __init__ (self, tDBfname, outputdir, charset, verstr):
        """ Initialize a new HtRep instance.  """
        Report.__init__(self, tDBfname, outputdir, verstr)
        self.rownumber = 0
        separatorID = 0

        for strLine in open(resource_filename('vinetto', 'data/HtRepTemplate.html'), "r").readlines():

            if strLine.find("__CHARSET__") > 0:
                strLine = strLine.replace("__CHARSET__", charset)
            if strLine.find("__ITS__") >= 0:
                separatorID += 1
                continue

            if separatorID == 0:
                HtHeader.append(strLine)
            elif separatorID == 1:
                HtPicRow.append(strLine)
            elif separatorID == 2:
                HtOrphans.append(strLine)
            elif separatorID == 3:
                HtFooter.append(strLine)

        self.TNidList = []
        self.TNtsList = []
        self.TNnameList = []


    def SetFileSection (self, FileSize, md5):
        """ Initialize data of the report file section.  """
        self.FileSize = FileSize
        self.md5 = md5


    def SetRE (self, tDBREcolor, tDBREpdid, tDBREndid, tDBREsdid, tDBREcid, tDBREuserflags,
                       tDBREctime, tDBREmtime, tDBREsid_firstSecDir, tDBREsid_sizeDir):
        """ Initialize data of the report file section.  """
        self.tDBREcolor = tDBREcolor
        self.tDBREpdid = tDBREpdid
        self.tDBREndid = tDBREndid
        self.tDBREsdid = tDBREsdid
        self.tDBREcid = tDBREcid
        self.tDBREuserflags = tDBREuserflags
        self.tDBREctime = tDBREctime
        self.tDBREmtime = tDBREmtime
        self.tDBREsid_firstSecDir = tDBREsid_firstSecDir
        self.tDBREsid_sizeDir = tDBREsid_sizeDir



    def headwrite (self):
        """ Writes report header.  """
        self.repfile = open(self.outputdir + "index.html", "w")
        for strLine in HtHeader:
            strLine = strLine.replace("__DATEREPORT__", "Report Date: " + ctime(time()))
            strLine = strLine.replace("__TDBDIRNAME__", self.tDBdirname)
            strLine = strLine.replace("__TDBFNAME__",   self.tDBfname)
            strLine = strLine.replace("__TDBMTIME__",   ctime(self.tDBmtime))
            strLine = strLine.replace("__FILESIZE__",   str(self.FileSize))
            strLine = strLine.replace("__MD5__",        self.md5)

            strLine = strLine.replace("__TDBRECOLOR__",  str(self.tDBREcolor))
            strLine = strLine.replace("__TDBREPDID__",   str(self.tDBREpdid))
            strLine = strLine.replace("__TDBRENDID__",   str(self.tDBREndid))
            strLine = strLine.replace("__TDBRESDID__",   str(self.tDBREsdid))
            strLine = strLine.replace("__TDBRECLASS__",  str(self.tDBREcid))
            strLine = strLine.replace("__TDBREUFLAGS__", str(self.tDBREuserflags))
            strLine = strLine.replace("__TDBRECTIME__",  self.tDBREctime)
            strLine = strLine.replace("__TDBREMTIME__",  self.tDBREmtime)
            strLine = strLine.replace("__TDBRESID1SD__", str(self.tDBREsid_firstSecDir))
            strLine = strLine.replace("__TDBRESIDSZD__", str(self.tDBREsid_sizeDir))

            self.repfile.write(strLine)


    def close(self, statstring):
        """ Terminate processing HtRep instance.  """

        for strLine in HtFooter:
            strLine = strLine.replace("__TYPEXTRACT__", statstring)
            strLine = strLine.replace("__VVERSION__", "Vinetto " + self.verstr)
            self.repfile.write(strLine)
        self.repfile.close()


    def rowflush(self):
        """ Process a report line.  """
        self.rownumber += 1
        for strLine in HtPicRow:
            strLine = strLine.replace("__ROWNUMBER__", str(self.rownumber))
            # Fill...
            for j in range(len(self.tnId)):
                strLine = strLine.replace("__TNfilled__" + str(j), "1")
                buff = IMGTAG.replace("__TNFNAME__", self.tnFname[j])
                buff = buff.replace("__TNNAME__", self.tnName[j])
                strLine = strLine.replace("__IMGTAG__" + str(j), buff)
                strLine = strLine.replace("__TNID__" + str(j), self.tnId[j])
            # Blank...
            for j in range(len(self.tnId),5):
                strLine = strLine.replace("__TNfilled__" + str(j), "0")
                strLine = strLine.replace("__IMGTAG__" + str(j), " &nbsp; ")
                strLine = strLine.replace("__TNID__" + str(j), " ")

            self.repfile.write(strLine)

        self.repfile.write("<TABLE WIDTH=\"720\"><TR><TD>&nbsp;</TD></TR>" +
                           "<TR><TD><P ALIGN=\"LEFT\">")
        for i in range(len(self.tnId)):
            if self.tnName[i] != "":
                self.repfile.write("<TT>" + self.tnId[i] + " -- " +
                               self.tnTs[i].replace("  ", " &nbsp;") + " -- " +
                               self.tnName[i] + "</TT><BR>\n")
            else:
                self.repfile.write("<TT STYLE=\"color: blue\">" + self.tnId[i] + " ** " +
                                   " no matching Catalog entry found " +
                                   " ** " + "</TT><BR>\n")

        self.repfile.write("</P></TD></TR><TR><TD>&nbsp;</TD></TR></TABLE>")

        self.tnId    = []
        self.tnFname = []
        self.tnTs    = []
        self.tnName  = []


    def printOrphanCatEnt(self, OrphanICat):
        """ Print orphan catalog entry.  """
        if OrphanICat != []:
            endOrphanSection = False
            for strLine in HtOrphans:
                if strLine.find("__ORPHANENTRY__") >= 0:
                    oprhanLine = strLine
                    break
                else:
                    self.repfile.write(strLine)

            for iCat in OrphanICat:
                catEntry = getCatEntry(iCat)
                Ts = catEntry[0][0]
                Name = catEntry[0][1]
                strTT = str("<TT>" + ("%04i" % iCat) + " -- " +
                        Ts.replace("  ", " &nbsp;") + " -- " + Name + "</TT><BR>\n")
                strLine = oprhanLine.replace("__ORPHANENTRY__", strTT)
                self.repfile.write(strLine)

            for strLine in HtOrphans:
                if strLine.find("__ORPHANENTRY__") < 0:
                    if endOrphanSection:
                        self.repfile.write(strLine)
                else:
                    endOrphanSection = True


    def flush(self, statstring):
        """ Process the report body and the report end.  """
        self.headwrite()

        self.rownumber = 0
        self.tnId    = []
        self.tnFname = []
        self.tnTs    = []
        self.tnName  = []

#        for (iTN, vType, filename) in TNStreams:
        for iTN in TNStreams:
            for (vType, filename) in TNStreams[iTN]:
                bFlush = False
                if (type(iTN) == unicode):
                    self.tnId.append(iTN)
                    bFlush = True
                else:
                    self.tnId.append("%04i" % iTN)
                self.tnFname.append(filename)
                catEntry = getCatEntry(iTN)
                if len(catEntry) == 0:
                    Ts = ""
                    Name = ""
                elif len(catEntry) >= 1:
                # duplicate index numbers not properly handled !!!
                    Ts = catEntry[0][0]
                    Name = catEntry[0][1]
                self.tnTs.append(Ts)
                self.tnName.append(Name)
                if (len(self.tnId) >= 5 or bFlush):
                    self.rowflush()

        if len(self.tnId) > 0:
            self.rowflush()

        # Scanning for orphan catalog entries
        OrphanICat = []
        for iCat in Catalog:
            if not TNStreams.has_key(iCat):
                OrphanICat.append(iCat)
        self.printOrphanCatEnt(OrphanICat)

        self.close(statstring)
