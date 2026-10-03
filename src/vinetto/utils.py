# -*- coding: UTF-8 -*-
"""
module utils.py
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumb Database files
 Copyright (C) 2005, 2006 by Michel Roukine
 Copyright (C) 2019-2026 by Keven L. Ates

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
file_micro = "2"

# Built-in...
import os
from time import strftime, gmtime

# Local...
import vinetto.config as config
import vinetto.error as verror

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
    dictTransTab = str.maketrans(strInChars, strOutChars)
    return strFileName.translate(dictTransTab)


def getEncoding():
    # What encoding do we use?
    if config.ARGS.utf8:
        return "utf8"
    else:
        return "iso-8859-1"


#def reencodeBytes(bytesString):
#    # Convert bytes encoded as utf-16-le to the global encoding...
#    return str(bytesString, "utf-16-le").encode(getEncoding(), "replace")


def decodeBytes(byteString):
    # Convert bytes encoded as utf-16-le to standard unicode...
    return str(byteString, "utf-16-le")


def prepareSymLink():
    if (not config.ARGS.symlinks):
        return

    strSymOut = getOutputPath(config.THUMBS_SUBDIR)
    if not os.path.exists(strSymOut):
        strError = " Error (Symlink): Cannot create directory '" + strSymOut + "' : "
        try:
            os.mkdir(strSymOut)
        except FileExistsError :
            raise verror.LinkError(strError + "Directory exists, but reported missing.")
        except FileNotFoundError:
            raise verror.LinkError(strError + "Parent directory not found.")
        except PermissionError:
            raise verror.LinkError(strError + "Insufficient permission.")
        except OSError as e:
            raise verror.LinkError(strError + "OS Error : {e}")
    return


def setSymlink(strTarget, strLink):
    strError = " Error (Symlink): Cannot create symlink '" + strLink + "' to file '" + strTarget + "' : "
    try:
        os.symlink(strTarget, strLink)
    except FileExistsError:
        raise verror.LinkError(strError + "Link already exists.")
    except PermissionError:
        raise verror.LinkError(strError + "Insufficient permission.")
    except FileNotFoundError:
        raise verror.LinkError(strError + "Link's directory structure not found.")
    except OSError as e:
        raise verror.LinkError(strError + "OS Error : {e}")
    return


def getTargetPath(strTargerDir, strFile):
    strOutDir = ""
    strPath = ""
    try :
        strOutDir = os.path.realpath(strTargerDir)
    except Exception as e:
        raise verror.InputError(" Error: Cannot get real path for '" + strTargerDir + "' : {e}")

    try :
        # Join the output path with the given file name string...
        strPath = os.path.join(strOutDir, strFile)
    except Exception as e:
        raise verror.InputError(" Error: Cannot join target path with file name '" + strFile + "' : {e}")

    try :
        strPath = os.path.realpath(strPath)
    except Exception as e:
        raise verror.InputError(" Error: Cannot get real path for '" + strPath + "' : {e}")

    bGood = strPath.startswith(strOutDir)
    if not bGood:
        raise verror.InputError(" Error: Target path '" + strPath + "' is not within the target directory '" + strTargerDir + "'")

    return strPath


def getOutputPath(strFile):
    strOutDir = ""
    strPath = ""
    try :
        strOutDir = os.path.realpath(config.ARGS.outdir)
    except Exception as e:
        raise verror.OutputError(" Error: Cannot get real path for '" + config.ARGS.outdir + "' : {e}")

    try :
        # Join the output path with the given file name string...
        strPath = os.path.join(strOutDir, strFile)
    except Exception as e:
        raise verror.OutputError(" Error: Cannot join output path with file name '" + strFile + "' : {e}")

    try :
        strPath = os.path.realpath(strPath)
    except Exception as e:
        raise verror.OutputError(" Error: Cannot get real path for '" + strPath + "' : {e}")

    bGood = strPath.startswith(strOutDir)
    if not bGood:
        raise verror.OutputError(" Error: Output path '" + strPath + "' is not within the output directory '" + config.ARGS.outdir + "'")

    return strPath

def appendSymLog(strTarget, strFileName):
    strFilePath = getOutputPath(config.THUMBS_FILE_SYMS)
    try:
        with open(strFilePath, "a+") as fileURL:
            fileURL.write(strTarget + " => " + strFileName + "\n")
            fileURL.close()
    except Exception as e:
        raise verror.OutputError(" Error: Cannot append to symlink log file '" + strFilePath + "' : {e}")
