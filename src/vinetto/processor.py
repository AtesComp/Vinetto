# -*- coding: UTF-8 -*-
"""
module processor.py
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
from __future__ import print_function


file_major = "0"
file_minor = "1"
file_micro = "9"


import sys
import os
import fnmatch

try:
    import vinetto.config as config
    import vinetto.report as report
    import vinetto.thumbOLE as thumbOLE
    import vinetto.thumbCMMM as thumbCMMM
    import vinetto.thumbIMMM as thumbIMMM
    import vinetto.utils as utils
    import vinetto.error as verror
except ImportError:
    import config
    import report
    import thumbOLE
    import thumbCMMM
    import thumbIMMM
    import utils
    import error as verror


###############################################################################
# Vinetto Processor Class
###############################################################################
class Processor():
    def __init__(self):
        # Initialize a new Processor instance...
        pass

    def processThumbFile(self, infile, filenames = None):
        # Open given Thumbnail file...
        try:
            fileThumbsDB = open(infile, "rb")
        except:
            strMsg = "Cannot open file " + infile
            if (config.ARGS.mode == "f"):  # ...only processing a single file, error
                raise verror.ProcessError(" Error (Process): " + strMsg)
            elif (config.ARGS.verbose >= 0):  # ...for modes "d", "r", and "a", continue
                sys.stderr.write(" Warning: " + strMsg + "\n")
            return

        # Setup file Header information...
        dictHead = {}
        dictHead["FilePath"] = infile
        dictHead["FileSize"] = None
        dictHead["MD5"] = None
        dictHead["FileType"] = None

        # Get file size of file...
        try:
            dictHead["FileSize"] = os.stat(infile).st_size
        except:
            strMsg = "Cannot get size of file " + infile
            if (config.ARGS.mode == "f"):  # ...only processing a single file, error
                raise verror.ProcessError(" Error (Process): " + strMsg)
            elif (config.ARGS.verbose >= 0):  # ...for modes "d", "r", and "a", continue
                sys.stderr.write(" Warning: " + strMsg + "\n")
            return

        # Get MD5 of file...
        if (config.ARGS.md5force) or ((not config.ARGS.md5never) and (dictHead["FileSize"] < (1024 ** 2) * 512)):
            try:
                # Python >= 2.5
                from hashlib import md5
                dictHead["MD5"] = md5(fileThumbsDB.read()).hexdigest()
            except:
                # Python < 2.5
                import md5
                dictHead["MD5"] = md5.new(fileThumbsDB.read()).hexdigest()
            del md5

        # -----------------------------------------------------------------------------
        # Begin analysis output...

        if (config.ARGS.verbose >= 0):
            print(config.STR_SEP)
            print(" File: %s" % dictHead["FilePath"])
            if (dictHead["MD5"] != None):
                print("  MD5: %s" % dictHead["MD5"])
            print(config.STR_SEP)

        # -----------------------------------------------------------------------------
        # Analyzing header block...

        iInitialOffset = 0
        fileThumbsDB.seek(0)
        bstrSig = fileThumbsDB.read(8)
        if   (bstrSig[0:8] == config.THUMBS_SIG_OLE):
            dictHead["FileType"] = config.THUMBS_TYPE_OLE
        elif (bstrSig[0:8] == config.THUMBS_SIG_OLEB):
            dictHead["FileType"] = config.THUMBS_TYPE_OLE
        elif (bstrSig[0:4] == config.THUMBS_SIG_CMMM):
            dictHead["FileType"] = config.THUMBS_TYPE_CMMM
        elif (bstrSig[0:4] == config.THUMBS_SIG_IMMM):
            dictHead["FileType"] = config.THUMBS_TYPE_IMMM
        elif (bstrSig[0:8] == bytearray(b"\x0c\x000 ") + config.THUMBS_SIG_IMMM):
            dictHead["FileType"] = config.THUMBS_TYPE_IMMM
            iInitialOffset = 4
        else:  # ...Header Signature not found...
            strMsg = "Header Signature not found in " + dictHead["FilePath"]
            if (config.ARGS.mode == "f"):
                raise verror.ProcessError(" Error (Process): " + strMsg)
            elif (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: " + strMsg + "\n")
            return  # ..always return

        # Initialize optional HTML report...
        if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
            config.HTTP_REPORT = report.HtmlReport(utils.getEncoding(), config.ARGS.outdir, dictHead)

        if (dictHead["FileType"] == config.THUMBS_TYPE_OLE):
            thumbOLE.process(dictHead["FilePath"], fileThumbsDB, dictHead["FileSize"])
        elif (dictHead["FileType"] == config.THUMBS_TYPE_CMMM):
            thumbCMMM.process(dictHead["FilePath"], fileThumbsDB, dictHead["FileSize"])
        elif (dictHead["FileType"] == config.THUMBS_TYPE_IMMM):
            thumbIMMM.process(dictHead["FilePath"], fileThumbsDB, dictHead["FileSize"], iInitialOffset)
        else:  # ...should never hit this as dictHead["FileType"] is set in prior "if" block above,
            # ...dictHead["FileType"] should always be set properly
            strMsg = "No process for Header Signature in " + dictHead["FilePath"]
            if (config.ARGS.mode == "f"):
                raise verror.ProcessError(" Error (Process): " + strMsg)
            elif (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: " + strMsg + "\n")

        return


    def processDirectory(self, thumbDir, filenames = None):
        # Search for thumbnail cache files:
        #  Thumbs.db, ehthumbs.db, ehthumbs_vista.db, Image.db, Video.db, TVThumb.db, and musicThumbs.db
        #
        #  thumbcache_*.db (2560, 1920, 1600, 1280, 1024, 768, 256, 96, 48, 32, 16, sr, wide, exif, wide_alternate, custom_stream)
        #  iconcache_*.db

        #includes = ['*humbs.db', '*humbs_*.db', 'Image.db', 'Video.db', 'TVThumb.db', 'thumbcache_*.db', 'iconcache_*.db']
        includes = ['*.db']

        if (filenames == None):
            filenames = []
            with os.scandir(thumbDir) as iterFiles:
                for fileEntry in iterFiles:
                    if fileEntry.is_file():
                        filenames.append(fileEntry.name)

        # Include files...
        tc_files = []
        for pattern in includes:
            for filename in fnmatch.filter(filenames, pattern):
                tc_files.append(os.path.join(thumbDir, filename))

        # TODO: Check for "Thumbs.db" file and related image files in current directory
        # TODO: This may involve passing info into processThumbFile() and following functionality
        # TODO: to check existing image file names against stored thumbnail IDs

        for thumbFile in tc_files:
            processThumbFile(thumbFile, filenames)

        return


    def processRecursiveDirectory(self):
        # Walk the directories from given directory recursively down...
        for dirpath, dirnames, filenames in os.walk(config.ARGS.infile):
            processDirectory(dirpath, filenames)

        return


    def processFileSystem(self):
        #
        # Process well known Thumb Cache DB files with ESE DB enhancement (if available)
        #

        strUserBaseDirVista = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_VISTA)
        strUserBaseDirXP = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_XP)

        # Vista+
        # ============================================================
        if os.path.isdir(strUserBaseDirVista):
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: FS - Detected a Windows Vista-like partition, processing each user's Thumbcache DB files\n")
            # For Vista+, only process the User's Explorer subdirectory containing Thumbcache DB files...
            with os.scandir(strUserBaseDirVista) as iterDirs:
                for entryUserDir in iterDirs:
                    if not entryUserDir.is_dir():
                        continue
                    userThumbsDir = os.path.join(entryUserDir.path, config.OS_WIN_THUMBCACHE_DIR)
                    if not os.path.exists(userThumbsDir):  # ...NOT exists?
                        if (config.ARGS.verbose >= 0):
                            sys.stderr.write(" Warning: Skipping %s - does not contain %s\n" % (entryUserDir.path, config.OS_WIN_THUMBCACHE_DIR))
                    else:
                        processDirectory(userThumbsDir)

        # XP
        # ============================================================
        elif os.path.isdir(strUserBaseDirXP):
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: FS - Detected a Windows XP-like partition, processing all user subdirectories\n")
            # For XP, only process each User's subdirectories...
            with os.scandir(strUserBaseDirXP) as iterDirs:
                for entryUserDir in iterDirs:
                    if not entryUserDir.is_dir():
                        continue
                    processDirectory(entryUserDir)

        # Other / Unidentified
        # ============================================================
        else:
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: FS - Generic partition, processing all subdirectories (recursive operating mode)\n")
            processDirectory(config.ARGS.infile)

        return
