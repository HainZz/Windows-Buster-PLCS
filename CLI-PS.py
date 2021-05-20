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
import wmi
import math
import win32api
import stat
import cups

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
    EicarAVTesting()
    DrivesInformation()
    DefenderConfiguration()
    UACConfiguration()
    NTLMSettings()
    GroupPolicy()
    AppLockerConfigBypass()
    Printers()
    NamedPipes()
    AsmiProviders()
    SysMon()
    NetVersions()


##SOURCE: http://timgolden.me.uk/python/wmi/cookbook.html
def DrivesInformation():
    c = wmi.WMI()
    print("\n" + "\033[1m" + Fore.RED + "Drives Information [*]" + Style.RESET_ALL + "\033[0m")
    DRIVE_TYPES = {0:"Unknown",1:"No Root Directory",2:"Removable Disk",3:"Local Disk",4:"Network Drive",5:"Compact Disc",6:"RAM Disk"}
    for drive in c.Win32_LogicalDisk():
        SpaceConversion = ByteConversion(drive.FreeSpace)
        caption = drive.Caption + "\\"
        File_Mode = os.stat(caption).st_mode
        Unix_Permissions = stat.filemode(File_Mode) #This gets unix like permissions on each of our drives using os.stat and stat modules
        InformationObject = win32api.GetVolumeInformation(caption)
        VolumeLabel = InformationObject[0]
        FileSystem = InformationObject[4]
        print('Caption: ' + Fore.CYAN + caption + " " + Style.RESET_ALL +
        'Type: ' + Fore.CYAN + DRIVE_TYPES[drive.DriveType] + " " + Style.RESET_ALL
        + 'Volume Label: ' + Fore.CYAN + VolumeLabel + Style.RESET_ALL + " " +
        'Avaliable Space: ' + Fore.CYAN + SpaceConversion + Style.RESET_ALL + " " +
        'File System: ' + Fore.CYAN + FileSystem + Style.RESET_ALL + " " +
        'File Permissions: ' + Fore.CYAN + Unix_Permissions + Style.RESET_ALL)

##SOURCE: https://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
def ByteConversion(Bytes):
    Bytes = int(Bytes)
    suffixes=["B","KB","MB","GB","TB"]
    suffixIndex = 0
    while Bytes > 1024 and suffixIndex < 4:
        suffixIndex += 1
        Bytes = Bytes/1024.0
    factor = 10 
    RoundedBytes = math.floor(Bytes * factor) / factor
    ConcatBytes = str(RoundedBytes) +" "+suffixes[suffixIndex]
    return ConcatBytes

def DefenderConfiguration():
    pass

##SOURCE : https://book.hacktricks.xyz/windows/authentication-credentials-uac-and-efs
def UACConfiguration():
    UAC_Options = {0:"No Prompting",1:"Prompt On Secure Desktop",2:"Prompt Permit Deny On Secure Desktop",3:"Prompt For Creds Not On Secure Desktop",
    4:"Prompt For Permit Deny Not On Secure Desktop",5:"Prompt For Non Windows Binaries"}
    Key_Index = 0
    Consent_Prompt_Admin = None
    Consent_Prompt_User = None
    LUA_Enabled = None
    LocalAccountToken = None
    AdminsitratorToken = None
    print("\n" + "\033[1m" + Fore.RED + "UAC Configuration [*]" + Style.RESET_ALL + "\033[0m")
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as machine_key:
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',0,winreg.KEY_READ) as UAC_key:
            while True:
                try:
                    KeyValue = winreg.EnumValue(UAC_key,Key_Index)
                    if KeyValue[0] == 'ConsentPromptBehaviorAdmin':
                        Consent_Prompt_Admin = KeyValue[1]
                    elif KeyValue[0] == 'ConsentPromptBehaviorUser':
                        Consent_Prompt_User = KeyValue[1]
                    elif KeyValue[0] == 'EnableLUA':
                        LUA_Enabled = KeyValue[1]
                    elif KeyValue[0] == 'LocalAccountTokenFilterPolicy':
                        LocalAccountToken = KeyValue[1]
                    elif KeyValue[0] == 'FilterAdministratorToken':
                        AdminsitratorToken = KeyValue[1]
                    Key_Index += 1
                except OSError:
                    break
    print("ConsentPromptBehaviorAdmin: " + Fore.CYAN + UAC_Options[Consent_Prompt_Admin] + Style.RESET_ALL)
    print("ConsentPromptBehaviorUser: " + Fore.CYAN + UAC_Options[Consent_Prompt_User] + Style.RESET_ALL)
    if LUA_Enabled == 1:
        print(Fore.GREEN + "LUA Enabled" + Style.RESET_ALL)
    else:
        print(Fore.RED + "LUA Disabled" + Style.RESET_ALL)
    if LocalAccountToken == 1:
        print(Fore.GREEN + "builds an elevated token" + Style.RESET_ALL)
    elif LocalAccountToken == 0:
        print(Fore.RED + "Builds an filtered token + the administrator credentials are removed" + Style.RESET_ALL)
    else:
        print("LocalAccountTokenFilterPolicy: " + Fore.CYAN + str(LocalAccountToken) + Style.RESET_ALL)
    if AdminsitratorToken == 1:
        print(Fore.GREEN + "Only the built-in adminstrator account (RID 500) is placed into admin approval mode/ Approval is required when performing admin tasks" + Style.RESET_ALL)
    elif AdminsitratorToken == 0:
        print(Fore.RED + "Only the built-in adminstrator account SHOULD be placed into full token mode" + Style.RESET_ALL)
    else:
        print("FilterAdministratorToken: " + Fore.CYAN + str(AdminsitratorToken) + Style.RESET_ALL)

#https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
#https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/f76c41f3c981382fdd21093e8f4498f6c41d92fd/winPEAS/winPEASexe/winPEAS/Info/SystemInfo/Ntlm/Ntlm.cs#L7
#https://blog.joeware.net/2018/07/07/5842/
#https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=NSrpcservers
def NTLMSettings():
    CompatibilityDict = {0:"Send LM & NTLM Responses",1:"Send LM & NTLM - use NTLMv2 session security if negotiated",2:"Send NTLM response only",3:"Send NTLMv2 response only",4:"Send NTLMv2 response only.Refuse LM",5:"Send NTLMv2 response only. Refuse LM & NTLM"}
    print("\n" + "\033[1m" + Fore.RED + "Enumerating NTLM Settings [*]" + Style.RESET_ALL + "\033[0m")
    Key_Index = 0
    LmCompatibilityLevel = None
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as machine_key:
        with winreg.OpenKey(machine_key,'System\\CurrentControlSet\\Control\\Lsa',0,winreg.KEY_READ) as CompatibilityLevelReg:
            while True:
                try:
                    LSA_Value = winreg.EnumValue(CompatibilityLevelReg, Key_Index)
                    if LSA_Value[0] == "LmCompatibilityLevel":
                        LmCompatibilityLevel = LSA_Value[1]
                        Key_Index += 1
                    Key_Index += 1
                except OSError:
                    break
        if LmCompatibilityLevel == None:
            print("LanManCompatibilityLevel: " + Fore.CYAN + CompatibilityDict[3] + Style.RESET_ALL)
        else:
            print("LanManCompatibilityLevel: " + Fore.CYAN + CompatibilityDict[LmCompatibilityLevel] + Style.RESET_ALL)
        with winreg.OpenKey(machine_key,'System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters',0,winreg.KEY_READ) as LanManWorkStation:
            ClientRequireSigning = winreg.EnumValue(LanManWorkStation, 2)[1]
            ClientNegotiateSigning = winreg.EnumValue(LanManWorkStation, 1)[1]
            if ClientRequireSigning == 1:
                print("ClientRequireSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
            else:
                print("ClientRequireSigning: " + Fore.RED + "False" + Style.RESET_ALL)
            if ClientNegotiateSigning == 1:
                print("ClientNegotiateSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
            else:
                print("ClientNegotiateSigning: " + Fore.RED + "False" + Style.RESET_ALL)
        with winreg.OpenKey(machine_key,'System\\CurrentControlSet\\Services\\LanManServer\\Parameters',0,winreg.KEY_READ) as LanManServer:
            ServerRequireSigning = winreg.EnumValue(LanManServer,6)[1]
            ServerNegotiateSigning = winreg.EnumValue(LanManServer,5)[1]
            if ServerRequireSigning == 1:
                print("ServerRequireSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
            else:
                print("ServerRequireSigning: " + Fore.RED + "False" + Style.RESET_ALL)
            if ServerNegotiateSigning == 1:
                print("ServerNegotiateSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
            else:
                print("ServerNegotiateSigning: " + Fore.RED + "False" + Style.RESET_ALL)
        with winreg.OpenKey(machine_key,'System\\CurrentControlSet\\Services\\LDAP',0,winreg.KEY_READ) as LDAPKey:
            LDAPSigning = winreg.EnumValue(LDAPKey,0)[1]
            if LDAPSigning == 1:
                print("LDAPSigning : Negotiate signing/sealing")
            elif LDAPSigning == 2:
                print("LDAPSigning : Require signing/sealing")
            else:
                print("LDAPSigning : No signing/sealing")
        with winreg.OpenKey(machine_key,'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',0,winreg.KEY_READ) as SessionSecKey:
            Key_Index = 0
            NTLMinClientSec = None
            NTLMinServerSec = None
            InboundRestrictions = None
            OutboundRestrictions = None
            InboundAuditing = None
            OutboundExceptions = None
            while True:
                try:
                    KeyValue = winreg.EnumValue(SessionSecKey,Key_Index)
                    if KeyValue[0] == "NtlmMinClientSec":
                        NTLMinClientSec = KeyValue[1]
                    elif KeyValue[0] == "NtlmMinServerSec":
                        NTLMinServerSec = KeyValue[1]
                    elif KeyValue[0] == "RestrictReceivingNTLMTraffic":
                        InboundRestrictions = KeyValue[1]
                    elif KeyValue[0] == "RestrictSendingNTLMTraffic":
                        OutboundRestrictions = KeyValue[1]
                    elif KeyValue[0] == "AuditReceivingNTLMTraffic":
                        InboundAuditing = KeyValue[1]
                    elif KeyValue[0] == "ClientAllowedNTLMServers":
                        OutboundExceptions = KeyValue[1]
                    Key_Index += 1
                except OSError:
                    break
            if NTLMinClientSec == 536870912:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "128-bit encryption. If the value of either this entry or the NtlmMinClientSec entry is 0x20000000, then the connection will fail unless 128-bit encryption is negotiated"
                + Style.RESET_ALL)
            elif NTLMinClientSec == 524288:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "NTLMv2 session security. If the value of either this entry or the NtlmMinClientSec entry is 0x80000, then the connection will fail unless NTLMv2 session security is negotiated."
                + Style.RESET_ALL)
            elif NTLMinClientSec == 32:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message confidentiality. If the value of either this entry or the NtlmMinClientSec entry is 0x20, then the connection will fail unless message confidentiality is negotiated."
                + Style.RESET_ALL)
            elif NTLMinClientSec == 16:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message integrity. If the value of either this entry or the NtlmMinClientSec entry is 0x10, then the connection will fail unless message integrity is negotiated."
                + Style.RESET_ALL)
            else:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "None. No security is used for session security."
                + Style.RESET_ALL)
            if NTLMinServerSec == 536870912:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "128-bit encryption. If the value of either this entry or the NtlmMinClientSec entry is 0x20000000, then the connection will fail unless 128-bit encryption is negotiated"
                + Style.RESET_ALL)
            elif NTLMinServerSec == 524288:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "NTLMv2 session security. If the value of either this entry or the NtlmMinClientSec entry is 0x80000, then the connection will fail unless NTLMv2 session security is negotiated."
                + Style.RESET_ALL)
            elif NTLMinServerSec == 32:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message confidentiality. If the value of either this entry or the NtlmMinClientSec entry is 0x20, then the connection will fail unless message confidentiality is negotiated."
                + Style.RESET_ALL)
            elif NTLMinServerSec == 16:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message integrity. If the value of either this entry or the NtlmMinClientSec entry is 0x10, then the connection will fail unless message integrity is negotiated."
                + Style.RESET_ALL)
            else:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "None. No security is used for session security."
                + Style.RESET_ALL)
            print("InboundRestrictions: " + Fore.CYAN + str(InboundRestrictions) + Style.RESET_ALL)
            print("OutboundRestrictions: " + Fore.CYAN + str(OutboundRestrictions) + Style.RESET_ALL)
            print("InboundAuditing: " + Fore.CYAN + str(InboundAuditing) + Style.RESET_ALL)
            print("OutboundExceptions: " + Fore.CYAN + str(OutboundExceptions) + Style.RESET_ALL)

def GroupPolicy():
    pass

def AppLockerConfigBypass():
    pass

def Printers():
    print("\n" + "\033[1m" + Fore.RED + "Printer Information [*]" + Style.RESET_ALL + "\033[0m")
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_Printer")
    for printer in colItems:
        print("Printer: " + Fore.CYAN + printer.Name + Style.RESET_ALL + " " + "Printer Status: " + 
        Fore.CYAN + printer.Status + Style.RESET_ALL + " " + "Network: " + Fore.CYAN + str(printer.Network) + 
        " " + Style.RESET_ALL + "Default: " + Fore.CYAN + str(printer.Default) + Style.RESET_ALL)


def NamedPipes():
    pass

def AsmiProviders():
    pass

def SysMon():
    pass

def NetVersions():
    print("\n"+ "\033[1m" + Fore.RED + "CLR & .NET Versions [*]" + Style.RESET_ALL + "\033[0m")
    CLRVersions = [] #Below this gets CLR Versions evey CLR as the file System.dll in it
    with os.scandir("\\Windows\\Microsoft.Net\\Framework\\") as entries:
        for entry in entries: #Get Directories in the powershell log file
            FullDir = "\\Windows\\Microsoft.Net\\Framework\\" + "\\" + entry.name
            try:
                with os.scandir(FullDir) as files:
                    for f in files:
                        if f.name == 'System.dll':
                            CLRVersions.append(entry.name)
            except NotADirectoryError:
                pass
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as machine_key:
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\NET Framework Setup\\NDP\\v3.5',0,winreg.KEY_READ) as dotNet35Version_Key:
            version = winreg.EnumValue(dotNet35Version_Key,4)[1]
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full',0,winreg.KEY_READ) as dotNet4Version_Key:
            version4 = winreg.EnumValue(dotNet4Version_Key,6)[1]
    print(Fore.MAGENTA + "CLR Versions Found:" + Style.RESET_ALL)
    for CLRversion in CLRVersions:
        print("CLR Version: " + Fore.CYAN + CLRversion + Style.RESET_ALL)
    print(Fore.MAGENTA + ".NET Versions:" + Style.RESET_ALL)
    print(".NET Version: " + Fore.CYAN + version + Style.RESET_ALL)
    print(".NET Version: " + Fore.CYAN + version4 + Style.RESET_ALL)

def EicarAVTesting():
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\SecurityCenter2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM AntiVirusProduct")
    print("\n" + "\033[1m" + Fore.RED + "Anti-Virus Information [*]" + Style.RESET_ALL + "\033[0m")
    for obj in colItems: #All anti-virus products have these options here we get information about all products on the windows system
        print("Product Display Name: " + Fore.CYAN + obj.displayName + Style.RESET_ALL)
        print("Instance GUID: " + Fore.CYAN + obj.instanceGuid + Style.RESET_ALL)
        print("Path To Signed Prodcut: " + Fore.CYAN + obj.pathToSignedProductExe + Style.RESET_ALL)
        if obj.displayName == "Windows Defender": #Specific information about windows defender product states all AV's have product states but i cant really put all of them in. 
            if obj.productState == 393472:
                print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL + Fore.RED + " Disabled & Up To Date" + Style.RESET_ALL)
            elif obj.productState == 397584:
                print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL + Fore.RED + " Enabled & Out Of Date" + Style.RESET_ALL)
            else:
                print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL + Fore.GREEN + " Enabled & Out Of Date" + Style.RESET_ALL)
        print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL)
        print("\n")
    spywareObjects = objSWbemServices.ExecQuery("SELECT * FROM AntiSpywareProduct")
    print("\n" + "\033[1m" + Fore.RED + "Anti-Spyware Information [*]" + Style.RESET_ALL + "\033[0m")
    for spyware in spywareObjects: 
        print("Spyware Product Display Name: " + Fore.CYAN + spyware.displayName + Style.RESET_ALL)
        print("Instance GUID: " + Fore.CYAN + spyware.instanceGuid + Style.RESET_ALL)
        print("Path To Signed Prodcut: " + Fore.CYAN + spyware.pathToSignedProductExe + Style.RESET_ALL)
        if spyware.displayName == "Windows Defender": #Specific information about windows defender product states all AV's have product states but i cant really put all of them in. 
            if spyware.productState == 393472:
                print("Product State: " +Fore.CYAN + str(spyware.productState) + Style.RESET_ALL + Fore.RED + " Disabled & Up To Date" + Style.RESET_ALL)
            elif spyware.productState == 397584:
                print("Product State: " +Fore.CYAN + str(spyware.productState) + Style.RESET_ALL + Fore.RED + " Enabled & Out Of Date" + Style.RESET_ALL)
            else:
                print("Product State: " +Fore.CYAN + str(spyware.productState) + Style.RESET_ALL + Fore.GREEN + " Enabled & Out Of Date" + Style.RESET_ALL)
        print("Product State: " + Fore.CYAN + str(spyware.productState) + Style.RESET_ALL)
        print("\n")
    FirewallObjects = objSWbemServices.ExecQuery("SELECT * FROM FirewallProduct")
    print("\n" + "\033[1m" + Fore.RED + "Firewall Product Information [*]" + Style.RESET_ALL + "\033[0m")
    for firewall in FirewallObjects:
        print("Firwall Product Display Name: " + Fore.CYAN + firewall.displayName + Style.RESET_ALL)
        print("Instance GUID: " + Fore.CYAN + firewall.instanceGuid + Style.RESET_ALL)
        print("Path To Signed Prodcut: " + Fore.CYAN + firewall.pathToSignedProductExe + Style.RESET_ALL)
        print("Product State: " + Fore.CYAN + str(firewall.productState) + Style.RESET_ALL)
        print("\n")


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
    
