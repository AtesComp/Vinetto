# -*- coding: UTF-8 -*-
"""
module utils.py
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
file_minor = "4"
file_micro = "0"


from sys import version_info as py_version_info
import os
import errno
from time import strftime, gmtime

try:
    import vinetto.config as config
    import vinetto.error as verror
except ImportError:
    import config
    import error as verror


def convertWinToPyTime(iFileTime_Win32):
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


def getFormattedWinToPyTimeUTC(iFileTime_Win32):
    if (iFileTime_Win32 == None):
        return "None"
    return getFormattedTimeUTC( convertWinToPyTime(iFileTime_Win32) )


def cleanFileName(strFileName):
    strInChars = "\\/:*?\"<>|"
    strOutChars = "_________"
    try:
        # Python >= 3
        dictTransTab = str.maketrans(strInChars, strOutChars)
        return strFileName.translate(dictTransTab)
    except:
        # Python < 3
        dictTransTab = {ord(c): ord(t) for c, t in zip(unicode(strInChars), unicode(strOutChars))}
        return strFileName.translate(dictTransTab)


def getEncoding():
    # What encoding do we use?
    if config.ARGS.utf8:
        return "utf8"
    else:
        return "iso-8859-1"


#def reencodeBytes(bytesString):
#    # Convert bytes encoded as utf-16-le to the global encoding...
#    if (py_version_info[0] < 3):
#        return unicode(bytesString, "utf-16-le").encode(getEncoding(), "replace")
#    else:
#        return str(bytesString, "utf-16-le").encode(getEncoding(), "replace")


def decodeBytes(byteString):
    # Convert bytes encoded as utf-16-le to standard unicode...
    if (py_version_info[0] < 3):
        return unicode(str(byteString), "utf-16-le")
    else:
        return str(byteString, "utf-16-le")


def prepareSymLink():
    if (not config.ARGS.symlinks):
        return

    strSymOut = config.ARGS.outdir + config.THUMBS_SUBDIR
    if not os.path.exists(strSymOut):
        try:
            os.mkdir(strSymOut)
        except EnvironmentError:
            raise verror.LinkError(" Error (Symlink): Cannot create directory " + strSymOut)
    return


def setSymlink(strTarget, strLink):
    try:
        os.symlink(strTarget, strLink)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(strLink)
            os.symlink(strTarget, strLink)
        else:
            raise verror.LinkError(" Error (Symlink): Cannot create symlink " + strLink + " to file " + strTarget)
    return


