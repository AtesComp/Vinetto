#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
module error.py
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

"""
Vinetto Errors are categorized by the return exit codes.

See the ReadMe.md file for more.
"""

import sys


ERROR = " Error"

class VinettoError(Exception):
    """
    Base class for exceptions in this module.
    """
    def __init__(self, *args):
        self.iExitCode = 1
        self.strErrHead = ERROR + ": "
        Exception.__init__(self, *args)

    def printError(self):
        sys.stderr.write(self.args[0] + "\n")


class InputError(VinettoError):
    """
    Exception raised for errors regarding input processing.
    """
    def __init__(self, *args):
        self.iExitCode = 10
        self.strErrHead = ERROR + " (Input): "
        VinettoError.__init__(self, *args)


class OutputError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 11
        self.strErrHead = ERROR + " (Output): "
        VinettoError.__init__(self, *args)


class ProcessError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 12
        self.strErrHead = ERROR + " (Process): "
        VinettoError.__init__(self, *args)


class InstallError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 13
        self.strErrHead = ERROR + " (Install): "
        VinettoError.__init__(self, *args)



class EntryError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 14
        self.strErrHead = ERROR + " (Entry): "
        VinettoError.__init__(self, *args)


class LinkError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 15
        self.strErrHead = ERROR + " (Link): "
        VinettoError.__init__(self, *args)


class ModeError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 16
        self.strErrHead = ERROR + " (Mode): "
        VinettoError.__init__(self, *args)


class ReportError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 17
        self.strErrHead = ERROR + " (Report): "
        VinettoError.__init__(self, *args)


class ESEDBError(VinettoError):
    """
    Exception raised for errors regarding output processing.
    """
    def __init__(self, *args):
        self.iExitCode = 18
        self.strErrHead = ERROR + " (ESEDB): "
        VinettoError.__init__(self, *args)

