import argparse
import os
import sys
from pathlib import Path
import winreg #Allows access to windows Registry
import colorama #Allows for coloured text to output little cool thing to add when using the program in CLI-MODE
from colorama import Fore,Back,Style
import platform
import ctypes
import win32com.client
import socket
import re


# This Tool was inspired by https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/72cf7d1ff0e5ea5bc36fee4e2bc0f52a2c38378c/winPEAS

def SystemInfo(FilePath):
    print("\033[1m" + Fore.MAGENTA + "SYSTEM INFORMATION [*]" + Style.RESET_ALL + "\033[0m")
    print("\n")
    PowerShellScript = open(FilePath,'w') #Opens The PowerShellScript file in the specified path. This is used to write system commands to run should we be unable to get updatermation using python methods. 
    PowerShellScript.write("systemupdate | Set-Content -Path .\Results.txt \n") #Write systemupdate to text file for user to use on WES.py
    BasicSystemInformation()
    WindowsUpdates()
    GetSettingsPSAudiitWefLaps()

#Source https://docs.microsoft.com/en-us/windows/win32/api/_wua/
#Source https://codereview.stackexchange.com/questions/135648/find-installed-and-available-windows-updates #Heres where i found out about the API downloaded the PDF and managed to figure some stuff out
#Reading this took two years of my lifespan to figure out the QueryHistory
def WindowsUpdates():
    WindowsUpdateList = []
    winupdateshitapi = win32com.client.Dispatch("Microsoft.Update.Searcher") #Allows us to create an instance of this interface by using the Microsoft.Update.Searcher program to create the object
    NoOfUpdates = winupdateshitapi.GetTotalHistoryCount()
    prievous_updates = winupdateshitapi.QueryHistory(0,NoOfUpdates) #Ordered Read-only list off IUpdateHistoryEntry Interfaces this function takes in a start index and a number of entries to grab in this case we want all so we get the total history
    for update in prievous_updates:
        Update_ID = re.findall(r'\(.*?\)',str(update.title))
        try:
            IDString = Update_ID[0]
        except IndexError: #Some values wont have an update ID therefore we need to make accomadation for this
            IDString = ''
        WindowsUpdateList.append([IDString,update.ClientApplicationID,update.Title,str(update.Date),update.Description])
    printWindowsUpdateList(WindowsUpdateList)

def printWindowsUpdateList(WindowsUpdateList):
    print("\033[1m" + Fore.RED + "WINDOWS UPDATE LIST [*]" + Style.RESET_ALL + "\033[0m")
    for update in WindowsUpdateList:
        print(Fore.GREEN + "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)
        print("ID : "+ Fore.CYAN + update[0] + Style.RESET_ALL)
        print("Client Application ID : "+ Fore.CYAN + update[1] + Style.RESET_ALL)
        print("Full Update Title : "+ Fore.CYAN + update[2] + Style.RESET_ALL)
        print("Date : "+ Fore.CYAN + update[3] + Style.RESET_ALL)
        print("Update Description : "+ Fore.CYAN + update[4] + Style.RESET_ALL)
        print(Fore.GREEN + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)

def GetSettingsPSAudiitWefLaps():
    PSSettings = GetPSSettings()
    AuditSettings = GetAuditSettings()
    WEFSettings = GetWefSettings()
    LAPSSettings = GetLapsSettings()
    PrintPSAuditWefLapsSettings(PSSettings,AuditSettings,WEFSettings,LAPSSettings)

#https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#powershell-transcript-files source on what settings are important too look for
def GetPSSettings():
    PSSettings = []
    HistoryLines = []
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hkey: #Get powershell version conatined within SOFTWARE\\Microsoft\\PowerShell directory
        with winreg.OpenKey(hkey,"SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine",0,winreg.KEY_READ) as ps_key_2:
                Powershell_version_2 = winreg.EnumValue(ps_key_2,3)[1]
                PSSettings.append(Powershell_version_2)
        with winreg.OpenKey(hkey,"SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine",0,winreg.KEY_READ) as ps_key_3:
                Powershell_version_5 = winreg.EnumValue(ps_key_3,3)[1]
                PSSettings.append(Powershell_version_5)
    #http://woshub.com/powershell-commands-history/#:~:text=By%20default%2C%20the%20PowerShell%20in,for%20PowerShell%20and%20PowerShell%20ISE.
    userprofile = os.environ['USERPROFILE']
    path = userprofile + "\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" #Default location for console_history files
    Count = 0
    with open(path,'r') as history_file:
        FileLines = history_file.readlines()
    for Line in FileLines:
        HistoryLines.append(Line)
        if Count == 30:
            break
    PSSettings.append(HistoryLines)
    return PSSettings


def GetAuditSettings():
    AuditSettings = []
    return AuditSettings

def GetWefSettings():
    WEFSettings = []
    return WEFSettings

def GetLapsSettings():
    LAPSSettings = []
    return LAPSSettings

def PrintPSAuditWefLapsSettings(PSSettings,AuditSettings,WEFSettings,LAPSSettings):
    pass

def BasicSystemInformation():
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hkey: #Get "root" key 
        KeyIndex = 0
        with winreg.OpenKey(hkey,"Software\\Microsoft\\Windows NT\\CurrentVersion",0,winreg.KEY_READ) as CurrentVersion_key: #Get subkey of root key
            while True: #Get values from what we want
                try:
                    key_name = winreg.EnumValue(CurrentVersion_key,KeyIndex)[0] #Get the name value at that index within the subkey
                    if key_name in ['ProductName','EditionID','ReleaseId','BuildBranch','CurrentMajorVersionNumber','CurrentVersion']: #Check name value matches a key we are looking for
                        if key_name == 'ProductName':
                            Product_Name = winreg.EnumValue(CurrentVersion_key,KeyIndex)[1] 
                            KeyIndex += 1 #Increment index to go to the next key
                        elif key_name == 'EditionID':
                            Edition_ID = winreg.EnumValue(CurrentVersion_key,KeyIndex)[1]
                            KeyIndex += 1
                        elif key_name == 'ReleaseId':
                            Release_ID = winreg.EnumValue(CurrentVersion_key,KeyIndex)[1]
                            KeyIndex += 1
                        elif key_name == 'BuildBranch':
                            Branch = winreg.EnumValue(CurrentVersion_key,KeyIndex)[1]
                            KeyIndex += 1
                        elif key_name == 'CurrentMajorVersionNumber':
                            CurrentMajorVersionNumber = winreg.EnumValue(CurrentVersion_key,KeyIndex)[1]
                            KeyIndex += 1
                        else:
                            Current_Version = winreg.EnumValue(CurrentVersion_key,KeyIndex)[1]
                            KeyIndex += 1
                    else:
                        KeyIndex += 1
                except OSError: #Once we reach the end of the subkey it will cause an OSError this is how we break out of the loop
                    break
    is_admin = CheckAdmin()
    is_VM = CheckVM()
    Hotfixes = Hotfix()
    PrintBasicOsInformation(Product_Name,Edition_ID,Release_ID,Branch,CurrentMajorVersionNumber,Current_Version,is_admin,is_VM)
    PrintMicrosoftHotfixes(Hotfixes)

def PrintMicrosoftHotfixes(Hotfixes):
    print("\n")
    print("\033[1m" + Fore.RED + "FOUND UPDATES [*]" + Style.RESET_ALL + "\033[0m")
    print("\n"+"\033[1m" + Fore.RED + "NON-SECURITY UPDATES [*]" + Style.RESET_ALL + "\033[0m")
    for hotfix in Hotfixes:
        if hotfix.Description != "Security Update":
            print(Fore.CYAN + "HotFixID:" + hotfix.HotFixID + "," + " Description:" + hotfix.Description +","+ " Installed By:" + hotfix.InstalledBy + "," + " Installed On:" +hotfix.InstalledOn + Style.RESET_ALL)
    print("\n"+"\033[1m" + Fore.RED + "SECURITY UPDATES [*]" + Style.RESET_ALL + "\033[0m")
    for hotfix in Hotfixes:
        if hotfix.Description == "Security Update":
            print(Fore.CYAN + "HotFixID:" + hotfix.HotFixID + "," + " Description:" + hotfix.Description +","+ " Installed By:" + hotfix.InstalledBy + "," + " Installed On:" +hotfix.InstalledOn + Style.RESET_ALL)
    print('\n')

def Hotfix():
    HotFixList = []
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_QuickFixEngineering")
    for hotfix in colItems:
        HotFixList.append(hotfix)
    return HotFixList

##TODO TEST THIS FUNCTION WITHIN A VM
## SOURCE: https://www.activexperts.com/admin/scripts/wmi/python/0383/
## SOURCE: https://stackoverflow.com/questions/498371/how-to-detect-if-my-application-is-running-in-a-virtual-machine
def CheckVM():
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_ComputerSystem")
    for obj in colItems:
        if obj.Manufacturer != None:
            manufacturer = obj.Manufacturer
        if obj.Model != None:
            model = obj.Model
    if (manufacturer == "microsoft corporation" and "VIRTUAL" in model.upper() or "vmware" in manufacturer or model == "VirtualBox"):
        return True
    else: #If any of these statements are true we can be confident that this a the machine is an VM
        return False

def CheckAdmin():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if is_admin == 0:
        is_admin = False
    else:
        is_admin = True
    return is_admin

def PrintBasicOsInformation(Product_Name,Edition_ID,Release_ID,Branch,CurrentMajorVersionNumber,Current_Version,is_admin,is_VM): #Simple print function for the basic OS portion of system information
    print("\033[1m" + Fore.RED + "BASIC OS INFORMATION [*]" + Style.RESET_ALL + "\033[0m")
    print(Fore.CYAN + 'User Name : ' + Style.RESET_ALL + os.environ['USERNAME'])
    print(Fore.CYAN + 'Computer Name : ' + Style.RESET_ALL + os.environ['COMPUTERNAME'])
    print(Fore.CYAN + 'Processor : ' + Style.RESET_ALL + platform.processor())
    print(Fore.CYAN + 'Architecture : ' + Style.RESET_ALL + platform.architecture()[0])
    print(Fore.CYAN + 'Machine : ' + Style.RESET_ALL + platform.machine())
    print(Fore.CYAN + 'ProductName : ' + Style.RESET_ALL + Product_Name)
    print(Fore.CYAN + 'EditionID : ' + Style.RESET_ALL + Edition_ID)
    print(Fore.CYAN + 'ReleaseID : ' + Style.RESET_ALL + Release_ID)
    print(Fore.CYAN + 'BuildBranch : ' + Style.RESET_ALL + Branch)
    print(Fore.CYAN + 'CurrentMajorVersionNumber : ' + Style.RESET_ALL + str(CurrentMajorVersionNumber))
    print(Fore.CYAN + 'Current_Version : ' + Style.RESET_ALL + str(Current_Version))
    if is_admin == False:
        print(Fore.CYAN + 'Process Running As Admin : ' + Style.RESET_ALL + str(is_admin))
    else:
        print(Fore.CYAN + 'Process Running As Admin : ' + Style.RESET_ALL + Fore.RED + str(is_admin) + Style.RESET_ALL)
    if is_VM == False:
        print(Fore.CYAN + 'Within A Virtual Machine : ' + Style.RESET_ALL + str(is_VM))
    else:
        print(Fore.CYAN + 'Process Running As Virtual Machine : ' + Style.RESET_ALL + Fore.RED + str(is_VM) + Style.RESET_ALL)
 
def Logging(FilePath):
    pass

def UserPrivileges(FilePath):
    pass

def Network(FilePath):
    pass

def Processes(FilePath):
    pass

def Services(FilePath):
    pass

def Applications(FilePath):
    pass

def PathDLL(FilePath):
    pass

def WindowsCredentials(FilePath):
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
        SystemInfo(arguments.FileOutput)
    if arguments.Logging == True:
        Logging(arguments.FileOutput)
    if arguments.UserPrivileges == True:
        UserPrivileges(arguments.FileOutput)
    if arguments.Network == True:
        Network(arguments.FileOutput)
    if arguments.Processes == True:
        Processes(arguments.FileOutput)
    if arguments.Services == True:
        Services(arguments.FileOutput)
    if arguments.Applications == True:
        Applications(arguments.FileOutput)
    if arguments.PathDLL == True:
        PathDLL(arguments.FileOutput)
    if arguments.WindowsCredentials == True:
        WindowsCredentials(arguments.FileOutput)
    
