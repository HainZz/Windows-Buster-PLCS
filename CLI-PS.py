import argparse
import os
import sys
from pathlib import Path

def SystemInfo():
    pass

def Logging():
    pass

def UserPrivileges():
    pass

def Network():
    pass

def Processes():
    pass

def Services():
    pass

def Applications():
    pass

def PathDLL():
    pass

def WindowsCredentials():
    pass

def Parse_Arguments():
    Valid_Short_Options = ['-S','-L','-U','-N','-P','-E','-A','-D','-W']
    Valid_Long_Options = ['--SystemInfo','--Logging','--UserPrivileges','--Network','--Processes','--Services','--Applications','--Services','--PathDLL','--WindowsCredentials','--FileOutput']
    parse = argparse.ArgumentParser()
    options = parse.add_mutually_exclusive_group(required=True)
    options.add_argument('-S','--SystemInfo',action='store_true',help='This optional argument will find OS version, system architecture, list patches/security patches & PowerShell history')
    options.add_argument('-L','--Logging',action='store_true',help='Provides user information on anti-virus and provides information on whether certain windows protections such as LSA protection is present')
    options.add_argument('-U','--UserPrivileges',action='store_true',help='Checks current users privileges + token clipboards and other information on users')
    options.add_argument('-N','--Network',action='store_true',help='Checks current information and lists of computer shares on the domain as well as its current shares etc. + Open Ports/DNS')
    options.add_argument('-P','--Processes',action='store_true',help='Lists all the current processes running on the system and checking permissions of the processes binaries and folders')
    options.add_argument('-E','--Services',action='store_true',help='Get a list of services running on the system and required privilege level for each service')
    options.add_argument('-A','--Applications',action='store_true',help='Checks permissions of binaries on the application and checking whether you can modify a binary or config file executed by a admin account')
    options.add_argument('-D','--PathDLL',action='store_true',help='Check whether write permissions exist inside a folder in PATH')
    options.add_argument('-W','--WindowsCredentials',action='store_true',help='Aims to check any credentials on the system such as those from WinLogon and any stored Wi-Fi connections as well as saved RDP connections and recently run commands')
    parse.add_argument('-F','--FileOutput',help='Directory/Filename where the powershell code shall be written too (note that if the file does not exist it will be created automatically',required=True)
    arguments = parse.parse_args()
    ArgumentsProvided = False
    OptionsProvided = False
    while ArgumentsProvided == False:
        SplitPath = arguments.FileOutput.rsplit('/',1)[0]
        if '/' not in SplitPath:
            SplitPath = './' 
        OutputPath = Path(SplitPath)
        if OutputPath.exists() == False:
            print('You must provide a valid output path')
            arguments.FileOutput = input('Please enter a valid output path : \n')
        else:
            ArgumentsProvided = True
    return arguments

if __name__ == '__main__':
    arguments = Parse_Arguments()
    if arguments.SystemInfo == True:
        SystemInfo(arguments.OutputPath)
    if arguments.Logging == True:
        Logging(arguments.OutputPath)
    if arguments.UserPrivileges == True:
        UserPrivileges(arguments.OutputPath)
    if arguments.Network == True:
        Network(arguments.OutputPath)
    if arguments.Processes == True:
        Processes(arguments.OutputPath)
    if arguments.Services == True:
        Services(arguments.OutputPath)
    if arguments.Applications == True:
        Applications(arguments.OutputPath)
    if arguments.PathDLL == True:
        PathDLL(arguments.OutputPath)
    if arguments.WindowsCredentials == True:
        WindowsCredentials(arguments.OutputPath)
    
