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
    EnviromentVariables()
    GetSettingsPSAudiitWefLaps()
    GetLSAProtection()
    CredentialGuard()
    WDigest()
    CachedCredentials()
    InternetSettings()

def InternetSettings():
    UserInternetSettings = GetUserInternetSettings()
    MachineInternetSettings = GetMachineInternetSettings()
    print("\n")
    print("\033[1m" + Fore.RED + "User Internet Settings [*]" + Style.RESET_ALL + "\033[0m")
    for user_key in UserInternetSettings:
        print(user_key + ":" + Fore.CYAN + str(UserInternetSettings[user_key]) + Style.RESET_ALL)
    print("\n")
    print("\033[1m" + Fore.RED + "Machine Internet Settings [*]" + Style.RESET_ALL + "\033[0m")
    for machine_key in MachineInternetSettings:
        print(machine_key + ":" + Fore.CYAN + str(MachineInternetSettings[machine_key]) + Style.RESET_ALL)

def GetUserInternetSettings():
    UserSettings = {}
    Key_Index = 0
    with winreg.ConnectRegistry(None,winreg.HKEY_CURRENT_USER) as user_key:
        with winreg.OpenKey(user_key,'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',0,winreg.KEY_READ) as Internet_Key:
            while True:
                try:
                    user_setting = winreg.EnumValue(Internet_Key,Key_Index)
                    UserSettings[user_setting[0]] = user_setting[1] #Add setting too our settings dict
                    Key_Index += 1
                except OSError:
                    break
    return UserSettings

def GetMachineInternetSettings():
    MachineSettings = {}
    Key_Index = 0
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as machine_key:
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',0,winreg.KEY_READ) as Internet_Key:
            while True:
                try:
                    machine_setting = winreg.EnumValue(Internet_Key, Key_Index)
                    MachineSettings[machine_setting[0]] = machine_setting[1]
                    Key_Index += 1
                except OSError:
                    break
    return MachineSettings

def CachedCredentials():
    print("\n")
    print("\033[1m" + Fore.RED + "Number Of Cached Credentials [*]" + Style.RESET_ALL + "\033[0m")
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as key:
        with winreg.OpenKey(key,'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',0,winreg.KEY_READ) as winlogon_key:
            Check_Cached_Credentials = winreg.EnumValue(winlogon_key,2)[1]
    print("NoOfCachedCredentials: " + Fore.GREEN + Check_Cached_Credentials + Style.RESET_ALL)
    
def WDigest():
    print("\n")
    print("\033[1m" + Fore.RED + "WDigest Settings [*]" + Style.RESET_ALL + "\033[0m")
    WDigestEnabled = 0
    Key_Index = 0
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as key:
        with winreg.OpenKey(key,'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',0,winreg.KEY_READ) as wdigest_key:
            while True:
                try:
                    Check_Key = winreg.EnumValue(wdigest_key,Key_Index)
                    if Check_Key[0] == "UseLogonCredential":
                        WDigestEnabled = Check_Key[1]
                    Key_Index += 1
                except OSError:
                    break
    if WDigestEnabled == 1:
        print(Fore.RED + "WDigest is active plain-text passwords could be stored in LSASS" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "WDigest is not active")

#https://ldapwiki.com/wiki/LSA%20Protection
def GetLSAProtection(): #Checks for LSA Protection. If enabled a driver is needed to read LSASSS memory
    print("\n")
    print("\033[1m" + Fore.RED + "LSA Protection/Settings [*]" + Style.RESET_ALL + "\033[0m")
    LSASettings = {}
    Key_Index = 0
    LSAEnabled = False
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as hkey:
        with winreg.OpenKey(hkey,'SYSTEM\\CurrentControlSet\\Control\\LSA',0,winreg.KEY_READ) as LSA_key:
            while True:
                try:
                    Check_LSA_Enabled = winreg.EnumValue(LSA_key,Key_Index)
                    LSASettings[Check_LSA_Enabled[0]] = Check_LSA_Enabled[1]
                    if Check_LSA_Enabled[0] == "RunAsPPL":
                        if Check_LSA_Enabled[1] == 1:
                            LSAEnabled = True
                    Key_Index += 1
                except OSError:
                    break
    print("LSAEnabled: " + Fore.CYAN + str(LSAEnabled) + Style.RESET_ALL)
    print("\n"+Fore.GREEN + "LSASettings: "+ Style.RESET_ALL)
    for key in LSASettings:
        print(key + ": " + Fore.CYAN + str(LSASettings[key]) + Style.RESET_ALL)

def CredentialGuard(): #Checks for credential guard if active a driver is needed to read LSASS memory
    #https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage READS Whether Credential Guard / Virtualization-Based-Security enabled
    print("\n")
    print("\033[1m" + Fore.RED + "Credential Guard [*]" + Style.RESET_ALL + "\033[0m")
    Key_Index = 0
    CredentialGuardEnabled = 0
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as hkey:
        with winreg.OpenKey(hkey,'SYSTEM\\CurrentControlSet\\Control\\LSA',0,winreg.KEY_READ) as LSA_key:
            while True:
                try:
                    Credential_Guard = winreg.EnumValue(LSA_key,Key_Index)
                    if Credential_Guard[0] == "LsaCfgFlags":
                        CredentialGuardEnabled = Credential_Guard[1]
                    Key_Index += 1
                except OSError:
                    break
    if CredentialGuardEnabled == 0:
        print(Fore.RED + "CREDENTIAL GUARD DISABLED" + Style.RESET_ALL)
    elif CredentialGuardEnabled == 1:
        print(Fore.GREEN + "CREDENTIAL GUARD ENABLED WITH UEFI LOCK" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "CREDENTIAL GUARD ENABLED WITHOUT UEFI LOCK" + Style.RESET_ALL)
    Key_Index = 0
    VirtualizationBasedSecurityEnabled = 0
    PlatformSecurityFeatures = 0
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as mkey:
        with winreg.OpenKey(mkey,'SYSTEM\\CurrentControlSet\\Control\\DeviceGuard',0,winreg.KEY_READ) as virtual_key:
            while True:
                try:
                    Virtualization_Entry = winreg.EnumValue(virtual_key,Key_Index)
                    if Virtualization_Entry[0] == "EnableVirtualizationBasedSecurity":
                        VirtualizationBasedSecurityEnabled = Virtualization_Entry[1]
                    elif Virtualization_Entry[0] == "RequirePlatformSecurityFeatures":
                        PlatformSecurityFeatures = Virtualization_Entry[1]
                    Key_Index += 1
                except OSError:
                    break
    print("\n")
    print("\033[1m" + Fore.RED + "Virtualization Based Security Settings [*]" + Style.RESET_ALL + "\033[0m")
    if VirtualizationBasedSecurityEnabled == 1:
        print(Fore.GREEN + "Virtualization Based Security Enabled" + Style.RESET_ALL)
    else:
        print(Fore.RED + "Virtualization Based Security Disabled" + Style.RESET_ALL)
    if PlatformSecurityFeatures == 1:
        print(Fore.GREEN + "Platform Security Feature Set Too Secure Boot Only" + Style.RESET_ALL)
    elif PlatformSecurityFeatures == 3:
        print(Fore.GREEN + "Platform Security Feature Set Too Secure Boot and DMCA Protection" + Style.RESET_ALL)
    else: #Catch any values not specified within the documentation this would be in the case of any werid configuration i couldnt find in documentation
        print(Fore.RED + "Unknown Value / Disabled Platformed Security Features Likely Enabled But Not Running" + Style.RESET_ALL)

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

def EnviromentVariables():
    SystemEnviromentVariables = {}
    UserEnvironmentVariables = {}
    Key_Index = 0
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as hkey:
        with winreg.OpenKey(hkey,'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment',0,winreg.KEY_READ) as sys_variables:
            while True: #Loop through till we reach the end of the registry because they can be 1-many system enviroment variables on a computer we must
                try:
                    system_variable = winreg.EnumValue(sys_variables,Key_Index)
                    SystemEnviromentVariables[system_variable[0]] = system_variable[1] #Add the Key-Value pair to the dictionary
                    Key_Index += 1
                except OSError:
                    break
    for key in os.environ:
        if key not in SystemEnviromentVariables:
            value = os.environ[key]
            UserEnvironmentVariables[key] = value
    print("\033[1m" + Fore.RED + "ENVIRONMENT VARIABLES [*]" + Style.RESET_ALL + "\033[0m" +"\n")
    print(Fore.GREEN + "SYSTEM VARIABLES : " + Style.RESET_ALL)
    for key in SystemEnviromentVariables:
        print("NAME : " + Fore.CYAN + key + Style.RESET_ALL + " VALUE : " + Fore.CYAN + SystemEnviromentVariables[key] + Style.RESET_ALL)
    print('\n')
    print(Fore.GREEN + "USER VARIABLES : " + Style.RESET_ALL)
    for key in UserEnvironmentVariables:
        print("NAME : " + Fore.CYAN + key + Style.RESET_ALL + " VALUE : " + Fore.CYAN + UserEnvironmentVariables[key] + Style.RESET_ALL)

def GetSettingsPSAudiitWefLaps():
    PSSettings = GetPSSettings()
    PrintPSSettings(PSSettings)

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
    PSSettings.append(path)
    Count = 0
    with open(path,'r') as history_file:
        FileLines = history_file.readlines()
    for Line in FileLines: #Get First 30 Lines of the ConsoleHost_history.txt file Shows Powershell History for attackers
        HistoryLines.append(Line)
        if Count == 30:
            break
        Count += 1
    PSSettings.append(HistoryLines)
    PowerShellSettings = {}
    #https://adamtheautomator.com/powershell-logging-2/#:~:text=You%20can%20also%20%E2%80%9Cstop%E2%80%9D%20a,folder%20and%20are%20named%20PowerShell_transcript. SOURCE CHECKS ONLY FOR REGISTRIES
    with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as mkey: #Get Local Machine Powershell Settings Note That This May Be Enabled But Cannot Be Found In Registries etc. Therefore this only checks registries if its enabled
        try:
            with winreg.OpenKey(mkey,"Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",0,winreg.KEY_READ) as Check_Script_Logging:
                MachineScriptBlockSetting = winreg.EnumValue(Check_Script_Logging,0)[1]
                if MachineScriptBlockSetting == 1:
                    PowerShellSettings['Machine_Script_Logging'] = True
                else:
                    PowerShellSettings['Machine_Script_Logging'] = False
        except FileNotFoundError:
            PowerShellSettings['Machine_Script_Logging'] = False
        try:
            with winreg.OpenKey(mkey,"Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",0,winreg.KEY_READ) as Check_Module_Logging:
                MachineModuleLoggingSetting = winreg.EnumValue(Check_Module_Logging,0)[1]
                if MachineScriptBlockSetting == 1:
                    PowerShellSettings['Machine_Module_Logging'] = True
                else:
                    PowerShellSettings['Machine_Script_Logging'] = False
        except FileNotFoundError:
            PowerShellSettings['Machine_Module_Logging'] = False
        try:
            with winreg.OpenKey(mkey,"Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",0,winreg.KEY_READ) as Check_Transcription:
                TranscriptionModuleLoggingSetting = winreg.EnumValue(Check_Transcription,0)[1] #Get Transcript settings i.e output directory whether its enabled / InvocationHeaders
                if TranscriptionModuleLoggingSetting == 1:
                    PowerShellSettings['Machine_Transcription_Logging'] = True
                    OutputDirectory = winreg.EnumValue(Check_Transcription,2)[1]
                    if OutputDirectory != '':
                        PowerShellSettings['Output_Directory_Setting'] = OutputDirectory
                    else:
                        PowerShellSettings['Output_Directory_Setting'] = 'C:\\transcripts'
                else:
                    PowerShellSettings['Machine_Transcription_Logging'] = False
        except FileNotFoundError:
            PowerShellSettings['Machine_Transcription_Logging'] = False
    PSSettings.append(PowerShellSettings)
    FileEntry={}
    with os.scandir(PowerShellSettings['Output_Directory_Setting']) as entries:
        for entry in entries: #Get Directories in the powershell log file
            FLine = []
            FullDir = PowerShellSettings['Output_Directory_Setting'] + "\\" + entry.name
            with os.scandir(FullDir) as files:
                for f in files:
                    FLine.append(f.name)
                FileEntry[entry.name] = FLine
    PSSettings.append(FileEntry)
    return PSSettings


def PrintPSSettings(PSSettings):
    LineCount = 0
    print("\n")
    print("\033[1m" + Fore.RED + "PowerShell Settings [*]" + Style.RESET_ALL + "\033[0m")
    print("PowerShell v2 Version: "+ Fore.CYAN + PSSettings[0] + Style.RESET_ALL)
    print("PowerShell v5 Version: "+ Fore.CYAN + PSSettings[1] + Style.RESET_ALL)
    print("Console History Location (DEFAULT): "+ Fore.CYAN + PSSettings[2] + Style.RESET_ALL)
    print(Fore.GREEN + "First 30 Lines Of Console History: " + Style.RESET_ALL)
    print("\n")
    for line in PSSettings[3]:
        print("LINE:",LineCount,Fore.CYAN+""+line+Style.RESET_ALL)
        LineCount += 1
    print(Fore.GREEN + "Script/Module/Transcription Settings Based of LOCAL MACHINE registry" + Style.RESET_ALL)
    print("\n")
    print("Machine_Script_Logging: ",Fore.RED+str(PSSettings[4]['Machine_Script_Logging'])+Style.RESET_ALL) #CHECKS IN LOCAL MACHINE REGISTRY
    print("Machine_Module_Logging: ",Fore.RED+str(PSSettings[4]['Machine_Module_Logging'])+Style.RESET_ALL)
    print("Machine_Transcription_Logging: ",Fore.RED+str(PSSettings[4]['Machine_Transcription_Logging'])+Style.RESET_ALL)
    print("Output_Directory_Transcription: ",Fore.RED+str(PSSettings[4]['Output_Directory_Setting'])+Style.RESET_ALL)
    print(Fore.GREEN + "Found Files Within Output_Directory [*]  Check These for cool transcripts with stuff in them." + Style.RESET_ALL)
    for key in PSSettings[5]:
        print(Fore.GREEN + "Found Files Within Directory " + Style.RESET_ALL + key + ":")
        for file in PSSettings[5][key]:
            print("File: "+ Fore.CYAN + file + Style.RESET_ALL)


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
    
