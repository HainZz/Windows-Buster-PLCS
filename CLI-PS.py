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
import subprocess

# This Tool was inspired by https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/72cf7d1ff0e5ea5bc36fee4e2bc0f52a2c38378c/winPEAS
def SystemInfo(FilePath):
    print("\033[1m" + Fore.MAGENTA + "SYSTEM INFORMATION [*]" + Style.RESET_ALL + "\033[0m")
    print("\n")
    PowerShellScript = open(FilePath.lstrip(),'w') #Opens The PowerShellScript file in the specified path. This is used to write system commands to run should we be unable to get updatermation using python methods. 
    subprocess.run(["powershell","-Command","systeminfo | Set-Content -Path .\Results.txt"]) #Runs the subprocess to produce the results.txt file
    #Order of running for CLI-PS we esentially just go through these procedurally
    BasicSystemInformation(PowerShellScript)
    WindowsUpdates(PowerShellScript)
    EnviromentVariables(PowerShellScript)
    GetSettingsPSAudiitWefLaps(PowerShellScript)
    GetLSAProtection(PowerShellScript)
    CredentialGuard(PowerShellScript)
    WDigest(PowerShellScript)
    CachedCredentials(PowerShellScript)
    InternetSettings(PowerShellScript)
    EicarAVTesting(PowerShellScript)
    DrivesInformation(PowerShellScript)
    UACConfiguration(PowerShellScript)
    NTLMSettings(PowerShellScript)
    Printers(PowerShellScript)
    NetVersions(PowerShellScript)


##SOURCE: http://timgolden.me.uk/python/wmi/cookbook.html
def DrivesInformation(PowerShellScript):
    c = wmi.WMI()
    print("\n" + "\033[1m" + Fore.RED + "Drives Information [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nDRIVES INFORMATION [*]")
    DRIVE_TYPES = {0:"Unknown",1:"No Root Directory",2:"Removable Disk",3:"Local Disk",4:"Network Drive",5:"Compact Disc",6:"RAM Disk"}
    #These are the different drive typtes the Win32_LogicalDisk can have.
    for drive in c.Win32_LogicalDisk():
        #Enumerate and get every drive object within Win32_LogicalDisk
        SpaceConversion = ByteConversion(drive.FreeSpace) #Call the byteconversion and convert this raw number of bytes into something a bit more displayable
        caption = drive.Caption + "\\"
        File_Mode = os.stat(caption).st_mode
        Unix_Permissions = stat.filemode(File_Mode) #This gets unix like permissions on each of our drives using os.stat and stat modules
        InformationObject = win32api.GetVolumeInformation(caption)#We utilise a win 32 API call to get some further information on a drive such as its file system + label
        VolumeLabel = InformationObject[0]
        FileSystem = InformationObject[4]
        print('Caption: ' + Fore.CYAN + caption + " " + Style.RESET_ALL +
        'Type: ' + Fore.CYAN + DRIVE_TYPES[drive.DriveType] + " " + Style.RESET_ALL
        + 'Volume Label: ' + Fore.CYAN + VolumeLabel + Style.RESET_ALL + " " +
        'Avaliable Space: ' + Fore.CYAN + SpaceConversion + Style.RESET_ALL + " " +
        'File System: ' + Fore.CYAN + FileSystem + Style.RESET_ALL + " " +
        'File Permissions: ' + Fore.CYAN + Unix_Permissions + Style.RESET_ALL)
        PowerShellScript.write('\nCaption: ' + caption + 'Type: ' + VolumeLabel + 'Avaliable Space: ' + SpaceConversion + 'File System: ' + FileSystem + 'File Permissions: ' + Unix_Permissions)
        #Big ass print statement and file write


##SOURCE: https://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
def ByteConversion(Bytes):
    #This functions takes in an float which repersents our bytes and converts it into a proper demonantion. i.e  instead of displaying 1024B we do 1KB etc.
    Bytes = int(Bytes)
    suffixes=["B","KB","MB","GB","TB"]
    suffixIndex = 0
    while Bytes > 1024 and suffixIndex < 4:
        suffixIndex += 1
        Bytes = Bytes/1024.0
    factor = 10 
    RoundedBytes = math.floor(Bytes * factor) / factor #I chose to always round down as its a better repersentation of avaliable space then rounding up.
    ConcatBytes = str(RoundedBytes) +" "+suffixes[suffixIndex]
    return ConcatBytes


##SOURCE : https://book.hacktricks.xyz/windows/authentication-credentials-uac-and-efs
def UACConfiguration(PowerShellScript):
    UAC_Options = {0:"No Prompting",1:"Prompt On Secure Desktop",2:"Prompt Permit Deny On Secure Desktop",3:"Prompt For Creds Not On Secure Desktop",
    4:"Prompt For Permit Deny Not On Secure Desktop",5:"Prompt For Non Windows Binaries"}
    #Different UAC options that the registies contain pretty cool found it on the above website.
    Key_Index = 0
    Consent_Prompt_Admin = None
    Consent_Prompt_User = None
    LUA_Enabled = None
    LocalAccountToken = None
    AdminsitratorToken = None
    #Initialize all our variables as None here as when we iterate over the registry we have no idea if these actually will be filled or even be in the registry
    print("\n" + "\033[1m" + Fore.RED + "UAC Configuration [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nUAC CONFIGURATION [*]")
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as machine_key:
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',0,winreg.KEY_READ) as UAC_key: #This UAC_key allows us to access all the Key,Value pairs we want
            while True:# This while loops enumerates over the registry until it reaches the end (osError) checking for whether it finds one of the keys we want above
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
    PowerShellScript.write("\nConsentPromptBehaviorAdmin: " + UAC_Options[Consent_Prompt_Admin]) #Call the value in the dictionary and print the description
    print("ConsentPromptBehaviorUser: " + Fore.CYAN + UAC_Options[Consent_Prompt_User] + Style.RESET_ALL)
    PowerShellScript.write("\nConsentPromptBehaviorUser: " + UAC_Options[Consent_Prompt_User])
    if LUA_Enabled == 1:
        print(Fore.GREEN + "LUA Enabled" + Style.RESET_ALL)
        PowerShellScript.write("\nLUA Enabled")
    else:
        print(Fore.RED + "LUA Disabled" + Style.RESET_ALL)
        PowerShellScript.write("\nLUA Disabled")
    if LocalAccountToken == 1:
        print(Fore.GREEN + "builds an elevated token" + Style.RESET_ALL)
        PowerShellScript.write("\nbuilds an elevated token")
    elif LocalAccountToken == 0:
        print(Fore.RED + "Builds an filtered token + the administrator credentials are removed" + Style.RESET_ALL)
        PowerShellScript.write("\nBuilds an filtered token + the administrator credentials are removed")
    else:
        print("LocalAccountTokenFilterPolicy: " + Fore.CYAN + str(LocalAccountToken) + Style.RESET_ALL)
        PowerShellScript.write("\nLocalAccountTokenFilterPolicy: " + str(LocalAccountToken))
    if AdminsitratorToken == 1:
        print(Fore.GREEN + "Only the built-in adminstrator account (RID 500) is placed into admin approval mode/ Approval is required when performing admin tasks" + Style.RESET_ALL)
        PowerShellScript.write("\nOnly the built-in adminstrator account (RID 500) is placed into admin approval mode/ Approval is required when performing admin tasks")
    elif AdminsitratorToken == 0:
        print(Fore.RED + "Only the built-in adminstrator account SHOULD be placed into full token mode" + Style.RESET_ALL)
        PowerShellScript.write("\nOnly the built-in adminstrator account SHOULD be placed into full token mode")
    else:
        print("FilterAdministratorToken: " + Fore.CYAN + str(AdminsitratorToken) + Style.RESET_ALL)
        PowerShellScript.write("\nFilterAdministratorToken: " + str(AdminsitratorToken))

#https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
#https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/f76c41f3c981382fdd21093e8f4498f6c41d92fd/winPEAS/winPEASexe/winPEAS/Info/SystemInfo/Ntlm/Ntlm.cs#L7
#https://blog.joeware.net/2018/07/07/5842/
#https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=NSrpcservers
def NTLMSettings(PowerShellScript):
    #Here is all the NTLM settings avaliable that we can search for. This dictionary allows us to match a number to description
    CompatibilityDict = {0:"Send LM & NTLM Responses",1:"Send LM & NTLM - use NTLMv2 session security if negotiated",2:"Send NTLM response only",3:"Send NTLMv2 response only",4:"Send NTLMv2 response only.Refuse LM",5:"Send NTLMv2 response only. Refuse LM & NTLM"}
    print("\n" + "\033[1m" + Fore.RED + "Enumerating NTLM Settings [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nENUMERATING NTLM SETTINGS [*]")
    Key_Index = 0
    LmCompatibilityLevel = None
    #Again enumerating over the registry as we did before
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
            print("LanManCompatibilityLevel: " + Fore.CYAN + CompatibilityDict[3] + Style.RESET_ALL) ##DEFAULT COMPATIBILTY LEVEL IF NONE IS FOUND I ASSUME THAT IT's THIS
            PowerShellScript.write("\nLanManCompatibilityLevel: " + CompatibilityDict[3])
        else:
            print("LanManCompatibilityLevel: " + Fore.CYAN + CompatibilityDict[LmCompatibilityLevel] + Style.RESET_ALL)
            PowerShellScript.write("\nLanManCompatibilityLevel: " + CompatibilityDict[LmCompatibilityLevel])
            #here this should unlesss something really werid is happening always be present and in the same index therefore we dont have to enumerate and instead use and specific index for KVP
            # Gets workstation settings (Client side) 
        with winreg.OpenKey(machine_key,'System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters',0,winreg.KEY_READ) as LanManWorkStation:
            ClientRequireSigning = winreg.EnumValue(LanManWorkStation, 2)[1]
            ClientNegotiateSigning = winreg.EnumValue(LanManWorkStation, 1)[1]
            if ClientRequireSigning == 1:
                print("ClientRequireSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
                PowerShellScript.write("\nClientRequireSigning: " + "True")
            else:
                print("ClientRequireSigning: " + Fore.RED + "False" + Style.RESET_ALL)
                PowerShellScript.write("\nClientRequireSigning: " + "False")
            if ClientNegotiateSigning == 1:
                print("ClientNegotiateSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
                PowerShellScript.write("\nClientNegotiateSigning: " + "True")
            else:
                print("ClientNegotiateSigning: " + Fore.RED + "False" + Style.RESET_ALL)
                PowerShellScript.write("\nClientNegotiateSigning: " + "False")
            #Gets Server Settings
        with winreg.OpenKey(machine_key,'System\\CurrentControlSet\\Services\\LanManServer\\Parameters',0,winreg.KEY_READ) as LanManServer:
            ServerRequireSigning = winreg.EnumValue(LanManServer,6)[1]
            ServerNegotiateSigning = winreg.EnumValue(LanManServer,5)[1]
            if ServerRequireSigning == 1:
                print("ServerRequireSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
                PowerShellScript.write("\nServerRequireSigning: " + "True")
            else:
                print("ServerRequireSigning: " + Fore.RED + "False" + Style.RESET_ALL)
                PowerShellScript.write("\nServerRequireSigning: " + "False")
            if ServerNegotiateSigning == 1:
                print("ServerNegotiateSigning: " + Fore.GREEN + "True" + Style.RESET_ALL)
                PowerShellScript.write("\nServerNegotiateSigning: " + "True")
            else:
                print("ServerNegotiateSigning: " + Fore.RED + "False" + Style.RESET_ALL)
                PowerShellScript.write("\nServerNegotiateSigning: " + "False")
            #Check for any LDAP settings again we have a registry here that dosent need to be enumerated
        with winreg.OpenKey(machine_key,'System\\CurrentControlSet\\Services\\LDAP',0,winreg.KEY_READ) as LDAPKey:
            LDAPSigning = winreg.EnumValue(LDAPKey,0)[1]
            if LDAPSigning == 1:
                print("LDAPSigning : Negotiate signing/sealing")
                PowerShellScript.write("\nLDAPSigning : Negotiate signing/sealing")
            elif LDAPSigning == 2:
                print("LDAPSigning : Require signing/sealing")
                PowerShellScript.write("\nLDAPSigning : Require signing/sealing")
            else:
                print("LDAPSigning : No signing/sealing")
                PowerShellScript.write("\nLDAPSigning : No signing/sealing")
        #Here we can't be 100% sure that these registries exist (at least on my windows 10 host they didnt) therefore we do some enumeration
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
            #For some reason NTLM has a really werid number scheme but here we esentially just do and if,elif chain printing the description that matches the number
            if NTLMinClientSec == 536870912:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "128-bit encryption. If the value of either this entry or the NtlmMinClientSec entry is 0x20000000, then the connection will fail unless 128-bit encryption is negotiated"
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinClientSec: " + str(NTLMinClientSec) + " " + "Description: " + "128-bit encryption. If the value of either this entry or the NtlmMinClientSec entry is 0x20000000, then the connection will fail unless 128-bit encryption is negotiated")
            elif NTLMinClientSec == 524288:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "NTLMv2 session security. If the value of either this entry or the NtlmMinClientSec entry is 0x80000, then the connection will fail unless NTLMv2 session security is negotiated."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinClientSec: " + str(NTLMinClientSec) + " " + "Description: " + "NTLMv2 session security. If the value of either this entry or the NtlmMinClientSec entry is 0x80000, then the connection will fail unless NTLMv2 session security is negotiated.")
            elif NTLMinClientSec == 32:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message confidentiality. If the value of either this entry or the NtlmMinClientSec entry is 0x20, then the connection will fail unless message confidentiality is negotiated."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinClientSec: " + str(NTLMinClientSec) + " " + "Description: " + "Message confidentiality. If the value of either this entry or the NtlmMinClientSec entry is 0x20, then the connection will fail unless message confidentiality is negotiated.")
            elif NTLMinClientSec == 16:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message integrity. If the value of either this entry or the NtlmMinClientSec entry is 0x10, then the connection will fail unless message integrity is negotiated."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinClientSec: " + str(NTLMinClientSec) + " " + "Description: " + "Message integrity. If the value of either this entry or the NtlmMinClientSec entry is 0x10, then the connection will fail unless message integrity is negotiated.")
            else:
                print("NTLMinClientSec: " + Fore.CYAN + str(NTLMinClientSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "None. No security is used for session security."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinClientSec: " + str(NTLMinClientSec) + " " + "Description: " + "None. No security is used for session security.")
            if NTLMinServerSec == 536870912:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "128-bit encryption. If the value of either this entry or the NtlmMinClientSec entry is 0x20000000, then the connection will fail unless 128-bit encryption is negotiated"
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinServerSec: " + str(NTLMinServerSec) + " " + "Description: " + "128-bit encryption. If the value of either this entry or the NtlmMinClientSec entry is 0x20000000, then the connection will fail unless 128-bit encryption is negotiated")
            elif NTLMinServerSec == 524288:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "NTLMv2 session security. If the value of either this entry or the NtlmMinClientSec entry is 0x80000, then the connection will fail unless NTLMv2 session security is negotiated."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinServerSec: " + str(NTLMinServerSec) + " " + "Description: " + "NTLMv2 session security. If the value of either this entry or the NtlmMinClientSec entry is 0x80000, then the connection will fail unless NTLMv2 session security is negotiated.")
            elif NTLMinServerSec == 32:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message confidentiality. If the value of either this entry or the NtlmMinClientSec entry is 0x20, then the connection will fail unless message confidentiality is negotiated."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinServerSec: " + str(NTLMinServerSec) + " " + "Description: " + "Message confidentiality. If the value of either this entry or the NtlmMinClientSec entry is 0x20, then the connection will fail unless message confidentiality is negotiated.")
            elif NTLMinServerSec == 16:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "Message integrity. If the value of either this entry or the NtlmMinClientSec entry is 0x10, then the connection will fail unless message integrity is negotiated."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinServerSec: " + str(NTLMinServerSec) + " " + "Description: " + "Message integrity. If the value of either this entry or the NtlmMinClientSec entry is 0x10, then the connection will fail unless message integrity is negotiated.")
            else:
                print("NTLMinServerSec: " + Fore.CYAN + str(NTLMinServerSec) + Style.RESET_ALL +" "+ "Description: " + Fore.CYAN + "None. No security is used for session security."
                + Style.RESET_ALL)
                PowerShellScript.write("\nNTLMinServerSec: " + str(NTLMinServerSec) + " " + "Description: " + "None. No security is used for session security.")
            print("InboundRestrictions: " + Fore.CYAN + str(InboundRestrictions) + Style.RESET_ALL)
            PowerShellScript.write("\nInboundRestrictions: " + str(InboundRestrictions))
            print("OutboundRestrictions: " + Fore.CYAN + str(OutboundRestrictions) + Style.RESET_ALL)
            PowerShellScript.write("\nOutboundRestrictions: " + str(OutboundRestrictions))
            print("InboundAuditing: " + Fore.CYAN + str(InboundAuditing) + Style.RESET_ALL)
            PowerShellScript.write("\nInboundAuditing: " + str(InboundAuditing))
            print("OutboundExceptions: " + Fore.CYAN + str(OutboundExceptions) + Style.RESET_ALL)
            PowerShellScript.write("\nOutboundExceptions: " + str(OutboundExceptions))


def Printers(PowerShellScript):
    print("\n" + "\033[1m" + Fore.RED + "Printer Information [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nPRINTER INFORMATION [*]")
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_Printer")
    #Here we get all objects from the root\cimv2 namespace and from Win32_Printer this contained all the printer information we needed
    for printer in colItems:
        print("Printer: " + Fore.CYAN + printer.Name + Style.RESET_ALL + " " + "Printer Status: " + 
        Fore.CYAN + printer.Status + Style.RESET_ALL + " " + "Network: " + Fore.CYAN + str(printer.Network) + 
        " " + Style.RESET_ALL + "Default: " + Fore.CYAN + str(printer.Default) + Style.RESET_ALL)
        PowerShellScript.write("\nPrinter: " + printer.Name + " " + "Printer Status: " + printer.Status + " " + "Network: " + str(printer.Network) + " " + "Default: " + str(printer.Default))

def NetVersions(PowerShellScript):
    print("\n"+ "\033[1m" + Fore.RED + "CLR & .NET Versions [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nCLR & .NET VERSIONS [*]")
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
    #These may change but these are the default .NET's on the system here we just get the version number from both there Keys in there respective registries
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as machine_key:
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\NET Framework Setup\\NDP\\v3.5',0,winreg.KEY_READ) as dotNet35Version_Key:
            version = winreg.EnumValue(dotNet35Version_Key,4)[1]
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full',0,winreg.KEY_READ) as dotNet4Version_Key:
            version4 = winreg.EnumValue(dotNet4Version_Key,6)[1]
    print(Fore.MAGENTA + "CLR Versions Found:" + Style.RESET_ALL)
    PowerShellScript.write("\nCLR Versions Found:")
    for CLRversion in CLRVersions:
        print("CLR Version: " + Fore.CYAN + CLRversion + Style.RESET_ALL)
        PowerShellScript.write("\nCLR Version: " + CLRversion)
    print(Fore.MAGENTA + ".NET Versions:" + Style.RESET_ALL)
    PowerShellScript.write("\n.NET Versions:")
    print(".NET Version: " + Fore.CYAN + version + Style.RESET_ALL)
    PowerShellScript.write("\n.NET Version: " + version)
    print(".NET Version: " + Fore.CYAN + version4 + Style.RESET_ALL)
    PowerShellScript.write("\n.NET Version: " + version4)

##SOURCE: https://ourcodeworld.com/articles/read/878/how-to-identify-detect-and-name-the-antivirus-software-installed-on-the-pc-with-c-on-winforms?fbclid=IwAR2MHFMR1qAm1QYG8JoXMOAnr8f2-nO99AHxcR45v-iWB-MUF2lIasrUVio
def EicarAVTesting(PowerShellScript):
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\SecurityCenter2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM AntiVirusProduct")
    #Very very useful here we can use the root\SecurityCenter2 and get a load of information from the AntiVirusProduct objects.
    print("\n" + "\033[1m" + Fore.RED + "Anti-Virus Information [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nANTI-VIRUS INFORMATION [*]")
    for obj in colItems: #All anti-virus products have these options here we get information about all products on the windows system
        print("Product Display Name: " + Fore.CYAN + obj.displayName + Style.RESET_ALL)
        PowerShellScript.write("\nProduct Display Name:" + obj.displayName)
        print("Instance GUID: " + Fore.CYAN + obj.instanceGuid + Style.RESET_ALL)
        PowerShellScript.write("\nInstance GUID: " + obj.instanceGuid)
        print("Path To Signed Prodcut: " + Fore.CYAN + obj.pathToSignedProductExe + Style.RESET_ALL)
        PowerShellScript.write("\nPath To Signed Product: " + obj.pathToSignedProductExe)
        if obj.displayName == "Windows Defender": #Specific information about windows defender product states all AV's have product states but i cant really put all of them in. 
            if obj.productState == 393472:
                print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL + Fore.RED + " Disabled & Up To Date" + Style.RESET_ALL)
                PowerShellScript.write("\nProduct State: " + str(obj.productState) + " Disabled & Up To Date")
            elif obj.productState == 397584:
                print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL + Fore.RED + " Enabled & Out Of Date" + Style.RESET_ALL)
                PowerShellScript.write("\nProduct State: " + str(obj.productState) + " Enabled & Out Of Date")
            else:
                print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL + Fore.GREEN + " Enabled & Up To Date" + Style.RESET_ALL)
                PowerShellScript.write("\nProduct State: " + str(obj.productState) + " Enabled & Up To Date")
        else:
            print("Product State: " +Fore.CYAN + str(obj.productState) + Style.RESET_ALL)
            PowerShellScript.write("\nProduct State: " + str(obj.productState))
        print("\n")
    #Get Spyware instead of AntiVirus
    spywareObjects = objSWbemServices.ExecQuery("SELECT * FROM AntiSpywareProduct")
    print("\n" + "\033[1m" + Fore.RED + "Anti-Spyware Information [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nANTI-SPYWARE INFORMATION [*]")
    for spyware in spywareObjects: 
        print("Spyware Product Display Name: " + Fore.CYAN + spyware.displayName + Style.RESET_ALL)
        PowerShellScript.write("\nSpyware Product Display Name: " + spyware.displayName)
        print("Instance GUID: " + Fore.CYAN + spyware.instanceGuid + Style.RESET_ALL)
        PowerShellScript.write("\nInstance GUID: " + spyware.instanceGuid)
        print("Path To Signed Prodcut: " + Fore.CYAN + spyware.pathToSignedProductExe + Style.RESET_ALL)
        PowerShellScript.write("\nPath To Signed Product: " + spyware.pathToSignedProductExe)
        if spyware.displayName == "Windows Defender": #Specific information about windows defender product states all AV's have product states but i cant really put all of them in without it being a massive task. Possible Area of expansion
            if spyware.productState == 393472:
                print("Product State: " +Fore.CYAN + str(spyware.productState) + Style.RESET_ALL + Fore.RED + " Disabled & Up To Date" + Style.RESET_ALL)
                PowerShellScript.write("\nProduct State: " + str(spyware.productState) + " Disabled & Up To Date")
            elif spyware.productState == 397584:
                print("Product State: " +Fore.CYAN + str(spyware.productState) + Style.RESET_ALL + Fore.RED + " Enabled & Out Of Date" + Style.RESET_ALL)
                PowerShellScript.write("\nProduct State: " + str(spyware.productState) + " Enabled & Out Of Date")
            else:
                print("Product State: " +Fore.CYAN + str(spyware.productState) + Style.RESET_ALL + Fore.GREEN + " Enabled & Up To Date" + Style.RESET_ALL)
                PowerShellScript.write("\nProduct State: " + str(spyware.productState) + " Enabled & Up To Date")
        else:
            print("Product State: " + Fore.CYAN + str(spyware.productState) + Style.RESET_ALL)
            PowerShellScript.write("\nProduct State: " + str(spyware.productState))
        print("\n")
    FirewallObjects = objSWbemServices.ExecQuery("SELECT * FROM FirewallProduct")
    print("\n" + "\033[1m" + Fore.RED + "Firewall Product Information [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nFIREWALL PRODUCT INFORMATION [*]")
    for firewall in FirewallObjects:
        print("Firwall Product Display Name: " + Fore.CYAN + firewall.displayName + Style.RESET_ALL)
        PowerShellScript.write("\nFirewall Product Display Name: " + firewall.displayName)
        print("Instance GUID: " + Fore.CYAN + firewall.instanceGuid + Style.RESET_ALL)
        PowerShellScript.write("\nInstance GUID: " + firewall.instanceGuid)
        print("Path To Signed Prodcut: " + Fore.CYAN + firewall.pathToSignedProductExe + Style.RESET_ALL)
        PowerShellScript.write("\nPath To Signed Product: " + firewall.pathToSignedProductExe)
        print("Product State: " + Fore.CYAN + str(firewall.productState) + Style.RESET_ALL)
        PowerShellScript.write("\nProduct State: " + str(firewall.productState))
        print("\n")


def InternetSettings(PowerShellScript):
    UserInternetSettings = GetUserInternetSettings() #Get a dict of settings from Respective registries
    MachineInternetSettings = GetMachineInternetSettings()
    print("\n")
    print("\033[1m" + Fore.RED + "User Internet Settings [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nUSER INTERNET SETTINGS [*]")
    #go through every key in the UserInternet dict print values.
    for user_key in UserInternetSettings:
        print(user_key + ":" + Fore.CYAN + str(UserInternetSettings[user_key]) + Style.RESET_ALL)
        PowerShellScript.write("\n"+user_key + ":" + str(UserInternetSettings[user_key]))
    print("\n")
    print("\033[1m" + Fore.RED + "Machine Internet Settings [*]" + Style.RESET_ALL + "\033[0m")
    #go through every key in the MachineInternet dict print values
    PowerShellScript.write("\nMACHINE INTERNET SETTINGS [*]")
    for machine_key in MachineInternetSettings:
        print(machine_key + ":" + Fore.CYAN + str(MachineInternetSettings[machine_key]) + Style.RESET_ALL)
        PowerShellScript.write("\n"+machine_key + ":" + str(MachineInternetSettings[machine_key]))

def GetUserInternetSettings():
    UserSettings = {}
    Key_Index = 0
    with winreg.ConnectRegistry(None,winreg.HKEY_CURRENT_USER) as user_key:
        #Get every single KVP from the registry
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
        #Get every single KVP from the registry
        with winreg.OpenKey(machine_key,'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',0,winreg.KEY_READ) as Internet_Key:
            while True:
                try:
                    machine_setting = winreg.EnumValue(Internet_Key, Key_Index)
                    MachineSettings[machine_setting[0]] = machine_setting[1]
                    Key_Index += 1
                except OSError:
                    break
    return MachineSettings

def CachedCredentials(PowerShellScript):
    print("\n")
    print("\033[1m" + Fore.RED + "Number Of Cached Credentials [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nNUMBER OF CACHED CREDENTIALS [*]")
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as key:
        #This is a default registry therefore we can use an set index
        with winreg.OpenKey(key,'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',0,winreg.KEY_READ) as winlogon_key:
            Check_Cached_Credentials = winreg.EnumValue(winlogon_key,2)[1]
    print("NoOfCachedCredentials: " + Fore.GREEN + Check_Cached_Credentials + Style.RESET_ALL)
    PowerShellScript.write("\nNoOfCachedCredentials:" + Check_Cached_Credentials)
    
def WDigest(PowerShellScript):
    #This function gets the wdigest settings dosent return anything just prints em.
    print("\n")
    print("\033[1m" + Fore.RED + "WDigest Settings [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nWDIGEST SETTINGS [*]")
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
        PowerShellScript.write("\nWDigest is active plain-text passwords could be stored in LSASS")
    else:
        print(Fore.GREEN + "WDigest is not active")
        PowerShellScript.write("\nWDigest is not active")

#https://ldapwiki.com/wiki/LSA%20Protection
def GetLSAProtection(PowerShellScript): #Checks for LSA Protection. If enabled a driver is needed to read LSASSS memory
    print("\n")
    print("\033[1m" + Fore.RED + "LSA Protection/Settings [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nLSA PROTECTION/SETTINGS [*]")
    LSASettings = {}
    Key_Index = 0
    LSAEnabled = False
    #Non-standard registry we must enumerate over it
    with winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE) as hkey:
        with winreg.OpenKey(hkey,'SYSTEM\\CurrentControlSet\\Control\\LSA',0,winreg.KEY_READ) as LSA_key:
            while True: #Here we get every key,value and store it in the LSASettings dict.
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
    PowerShellScript.write("\nLSAEnabled: " + str(LSAEnabled))
    print("\n"+Fore.GREEN + "LSASettings: "+ Style.RESET_ALL)
    PowerShellScript.write("\nLSASettings: ")
    #Here we get every key and print out there value and save it to the output file.
    for key in LSASettings:
        print(key + ": " + Fore.CYAN + str(LSASettings[key]) + Style.RESET_ALL)
        PowerShellScript.write("\n"+key+":"+str(LSASettings[key]))

def CredentialGuard(PowerShellScript): #Checks for credential guard if active a driver is needed to read LSASS memory
    #https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage READS Whether Credential Guard / Virtualization-Based-Security enabled
    print("\n")
    print("\033[1m" + Fore.RED + "Credential Guard [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nCREDENTIAL GUARD [*]")
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
    #Credential guard has 3 numbers that i could identify 0-2 i used this else assuming that someone wouldnt change credential guard to something werid like 2000
    if CredentialGuardEnabled == 0:
        print(Fore.RED + "CREDENTIAL GUARD DISABLED" + Style.RESET_ALL)
        PowerShellScript.write("\nCREDENTIAL GUARD DISABLED")
    elif CredentialGuardEnabled == 1:
        print(Fore.GREEN + "CREDENTIAL GUARD ENABLED WITH UEFI LOCK" + Style.RESET_ALL)
        PowerShellScript.write("\nCREDENTIAL GUARD ENABLED WITH UEFI LOCK")
    else:
        print(Fore.GREEN + "CREDENTIAL GUARD ENABLED WITHOUT UEFI LOCK" + Style.RESET_ALL)
        PowerShellScript.write("\nCREDENTIAL GUARD ENABLED WITHOUT UEFI LOCK")
    Key_Index = 0
    VirtualizationBasedSecurityEnabled = 0
    PlatformSecurityFeatures = 0
    #Predefine variables just in case we dont find it in the registry
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
    #Get virtualization and platfor security settings using there various number ID's that correspond to various settings
    print("\n")
    print("\033[1m" + Fore.RED + "Virtualization Based Security Settings [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nVIRTUALIZATION BASED SECURITY SETTINGS [*]")
    if VirtualizationBasedSecurityEnabled == 1:
        print(Fore.GREEN + "Virtualization Based Security Enabled" + Style.RESET_ALL)
        PowerShellScript.write("\nVirtualization Based Security Enabled")
    else:
        print(Fore.RED + "Virtualization Based Security Disabled" + Style.RESET_ALL)
        PowerShellScript.write("\nVirtualization Based Security Disabled")
    if PlatformSecurityFeatures == 1:
        print(Fore.GREEN + "Platform Security Feature Set Too Secure Boot Only" + Style.RESET_ALL)
        PowerShellScript.write("\nPlatform Security Feature Set Too Secure Boot Only")
    elif PlatformSecurityFeatures == 3:
        print(Fore.GREEN + "Platform Security Feature Set Too Secure Boot and DMCA Protection" + Style.RESET_ALL)
        PowerShellScript.write("\nPlatform Security Feature Set Too Secure Boot and DMCA Protection")
    else: #Catch any values not specified within the documentation this would be in the case of any werid configuration i couldnt find in documentation
        print(Fore.RED + "Unknown Value / Disabled Platformed Security Features Likely Enabled But Not Running" + Style.RESET_ALL)
        PowerShellScript.write("\nUnknown Value / Disabled Platformed Security Features Likely Enabled But Not Running")

#Source https://docs.microsoft.com/en-us/windows/win32/api/_wua/
#Source https://codereview.stackexchange.com/questions/135648/find-installed-and-available-windows-updates #Heres where i found out about the API downloaded the PDF and managed to figure some stuff out
#Reading this took two years of my lifespan to figure out the QueryHistory
def WindowsUpdates(PowerShellScript):
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
    printWindowsUpdateList(WindowsUpdateList,PowerShellScript)

def printWindowsUpdateList(WindowsUpdateList,PowerShellScript):
    #Simply print function just for some seperation. Takes in the WindowsUpdateList and prints every update found within the WindowsUpdateList
    print("\033[1m" + Fore.RED + "WINDOWS UPDATE LIST [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nWINDOWS UPDATE LIST [*]")
    for update in WindowsUpdateList:
        print(Fore.GREEN + "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)
        print("ID : "+ Fore.CYAN + update[0] + Style.RESET_ALL)
        print("Client Application ID : "+ Fore.CYAN + update[1] + Style.RESET_ALL)
        print("Full Update Title : "+ Fore.CYAN + update[2] + Style.RESET_ALL)
        print("Date : "+ Fore.CYAN + update[3] + Style.RESET_ALL)
        print("Update Description : "+ Fore.CYAN + update[4] + Style.RESET_ALL)
        print(Fore.GREEN + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + Style.RESET_ALL)
        PowerShellScript.write("\nID: " + update[0] + "\n" + "Client Application ID: " + update[1] + "\n" + "Full Update Title: " + update[2] + "\n" + "Date: " + update[3] + "\n" + "Update Description: " + update[4] + "\n")

def EnviromentVariables(PowerShellScript):
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
    #Above we get specific system-enviroment variables compare them to the list of all env variables (os.environ) and seperate them out into 2 columns those that are user and those that are system
    print("\033[1m" + Fore.RED + "ENVIRONMENT VARIABLES [*]" + Style.RESET_ALL + "\033[0m" +"\n")
    PowerShellScript.write("\nENVIRONMENT VARIABLES [*]")
    print(Fore.GREEN + "SYSTEM VARIABLES : " + Style.RESET_ALL)
    PowerShellScript.write("\n\nSYSTEM VARIABLES : ")
    for key in SystemEnviromentVariables:
        print("NAME : " + Fore.CYAN + key + Style.RESET_ALL + " VALUE : " + Fore.CYAN + SystemEnviromentVariables[key] + Style.RESET_ALL)
        PowerShellScript.write("\nNAME : " + key + "VALUE : " + SystemEnviromentVariables[key])
    print('\n')
    print(Fore.GREEN + "USER VARIABLES : " + Style.RESET_ALL)
    PowerShellScript.write("\n\nUSER VARIABLES : ")
    for key in UserEnvironmentVariables:
        print("NAME : " + Fore.CYAN + key + Style.RESET_ALL + " VALUE : " + Fore.CYAN + UserEnvironmentVariables[key] + Style.RESET_ALL)
        PowerShellScript.write("\nNAME : " + key + "VALUE : " + UserEnvironmentVariables[key])

def GetSettingsPSAudiitWefLaps(PowerShellScript):
    PSSettings = GetPSSettings() #Returns a list of various ps settings such as powershell versions transcripts etc.
    PrintPSSettings(PSSettings,PowerShellScript)

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


def PrintPSSettings(PSSettings,PowerShellScript):
    LineCount = 0
    print("\n")
    print("\033[1m" + Fore.RED + "PowerShell Settings [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nPOWERSHELL SETTINGS [*]")
    print("PowerShell v2 Version: "+ Fore.CYAN + PSSettings[0] + Style.RESET_ALL)
    PowerShellScript.write("\nPowerShell v2 Version: " + PSSettings[0])
    print("PowerShell v5 Version: "+ Fore.CYAN + PSSettings[1] + Style.RESET_ALL)
    PowerShellScript.write("\nPowerShell v5 Version: " + PSSettings[1])
    print("Console History Location (DEFAULT): "+ Fore.CYAN + PSSettings[2] + Style.RESET_ALL)
    PowerShellScript.write("\nConsole History Location (DEFAULT): " + PSSettings[2])
    print(Fore.GREEN + "First 30 Lines Of Console History: " + Style.RESET_ALL)
    PowerShellScript.write("\nFirst 30 Lines Of Console History: ")
    print("\n")
    for line in PSSettings[3]:
        print("LINE:",LineCount,Fore.CYAN+""+line+Style.RESET_ALL)
        PowerShellScript.write("LINE:" + line)
        LineCount += 1
    print(Fore.GREEN + "Script/Module/Transcription Settings Based of LOCAL MACHINE registry" + Style.RESET_ALL)
    PowerShellScript.write("SCRIPT/MODULE/TRANSCRIPTION SETTINGS BASED OF LOCAL MACHINE REGISTRY [*]")
    print("\n")
    print("Machine_Script_Logging: ",Fore.RED+str(PSSettings[4]['Machine_Script_Logging'])+Style.RESET_ALL) #CHECKS IN LOCAL MACHINE REGISTRY
    PowerShellScript.write("\nMachine_Script_Logging:" + str(PSSettings[4]['Machine_Script_Logging']))
    print("Machine_Module_Logging: ",Fore.RED+str(PSSettings[4]['Machine_Module_Logging'])+Style.RESET_ALL)
    PowerShellScript.write("\nMachine_Module_Logging:" + str(PSSettings[4]['Machine_Module_Logging']))
    print("Machine_Transcription_Logging: ",Fore.RED+str(PSSettings[4]['Machine_Transcription_Logging'])+Style.RESET_ALL)
    PowerShellScript.write("\nMachine_Transcription_Logging" + str(PSSettings[4]['Machine_Transcription_Logging']))
    print("Output_Directory_Transcription: ",Fore.RED+str(PSSettings[4]['Output_Directory_Setting'])+Style.RESET_ALL)
    PowerShellScript.write("\nOutput_Directory_Transcription"+str(PSSettings[4]['Output_Directory_Setting']))
    print(Fore.GREEN + "Found Files Within Output_Directory [*]  Check These for cool transcripts with stuff in them." + Style.RESET_ALL)
    PowerShellScript.write("\n\nFound Files Within Output_Directory [*] Check These for cool transcripts with stuff in them.")
    for key in PSSettings[5]:
        print(Fore.GREEN + "Found Files Within Directory " + Style.RESET_ALL + key + ":")
        PowerShellScript.write("\nFound Files Within Directory " + key + ":")
        for file in PSSettings[5][key]:
            print("File: "+ Fore.CYAN + file + Style.RESET_ALL)
            PowerShellScript.write("\nFile: " + file)
        PowerShellScript.write("\n")


def BasicSystemInformation(PowerShellScript):
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
    is_admin = CheckAdmin() #Returns a boolean stating whether were running as an admin or not
    is_VM = CheckVM() #Returns a boolean stating whether we are running as an admin or not
    Hotfixes = Hotfix() #Returns a list of hotfixes
    PrintBasicOsInformation(Product_Name,Edition_ID,Release_ID,Branch,CurrentMajorVersionNumber,Current_Version,is_admin,is_VM,PowerShellScript)
    PrintMicrosoftHotfixes(Hotfixes,PowerShellScript) #Simple print function that we can enumerate and list all the hotfixes applied to the system

def PrintMicrosoftHotfixes(Hotfixes,PowerShellScript):
    print("\n")
    print("\033[1m" + Fore.RED + "FOUND UPDATES [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nFOUND UPDATES [*]")
    print("\n"+"\033[1m" + Fore.RED + "NON-SECURITY UPDATES [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nNON-SECURITY UPDATES [*]")
    for hotfix in Hotfixes:
        if hotfix.Description != "Security Update":
            print(Fore.CYAN + "HotFixID:" + hotfix.HotFixID + "," + " Description:" + hotfix.Description +","+ " Installed By:" + hotfix.InstalledBy + "," + " Installed On:" +hotfix.InstalledOn + Style.RESET_ALL)
            PowerShellScript.write("\nHotFixID:" + hotfix.HotFixID + "," + " Description:" + hotfix.Description + "," + " Installed By:" + hotfix.InstalledBy + "," + " Installed On:" + hotfix.InstalledOn)
    print("\n"+"\033[1m" + Fore.RED + "SECURITY UPDATES [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("\nSECURITY UPDATES [*]")
    for hotfix in Hotfixes:
        if hotfix.Description == "Security Update":
            print(Fore.CYAN + "HotFixID:" + hotfix.HotFixID + "," + " Description:" + hotfix.Description +","+ " Installed By:" + hotfix.InstalledBy + "," + " Installed On:" +hotfix.InstalledOn + Style.RESET_ALL)
            PowerShellScript.write("\nHotFixID:" + hotfix.HotFixID + "," + " Description:" + hotfix.Description + "," + " Installed By:" + hotfix.InstalledBy + "," + " Installed On:" + hotfix.InstalledOn)
    print('\n')

def Hotfix():
    HotFixList = []
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_QuickFixEngineering")
    #This gets every hotfix within the Win32_QuickFixEngineering object. 
    for hotfix in colItems:
        HotFixList.append(hotfix)
    return HotFixList

## SOURCE: https://www.activexperts.com/admin/scripts/wmi/python/0383/
## SOURCE: https://stackoverflow.com/questions/498371/how-to-detect-if-my-application-is-running-in-a-virtual-machine
def CheckVM():
    strComputer = "."
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
    colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_ComputerSystem") #This basically checks a bunch of common stuff for an VM this aims to cover most stuff but likely some obscure VM program wouldnt be covered
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
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() #We can use ctyped to check whether we are running as an administrator user 
    if is_admin == 0:
        is_admin = False
    else:
        is_admin = True
    return is_admin

def PrintBasicOsInformation(Product_Name,Edition_ID,Release_ID,Branch,CurrentMajorVersionNumber,Current_Version,is_admin,is_VM,PowerShellScript): #Simple print function for the basic OS portion of system information
    print("\033[1m" + Fore.RED + "BASIC OS INFORMATION [*]" + Style.RESET_ALL + "\033[0m")
    PowerShellScript.write("BASIC OS INFORMATION [*]")
    print(Fore.CYAN + 'User Name : ' + Style.RESET_ALL + os.environ['USERNAME'])
    PowerShellScript.write("\nUser Name : " + os.environ['USERNAME'])
    print(Fore.CYAN + 'Computer Name : ' + Style.RESET_ALL + os.environ['COMPUTERNAME'])
    PowerShellScript.write("\nComputer Name : " + os.environ['COMPUTERNAME'])
    print(Fore.CYAN + 'Processor : ' + Style.RESET_ALL + platform.processor())
    PowerShellScript.write("\nProcessor : " + platform.processor())
    print(Fore.CYAN + 'Architecture : ' + Style.RESET_ALL + platform.architecture()[0])
    PowerShellScript.write("\nArchitecture : " + platform.architecture()[0])
    print(Fore.CYAN + 'Machine : ' + Style.RESET_ALL + platform.machine())
    PowerShellScript.write("\nMachine : " + platform.machine())
    print(Fore.CYAN + 'ProductName : ' + Style.RESET_ALL + Product_Name)
    PowerShellScript.write("\nProductName : " + Product_Name)
    print(Fore.CYAN + 'EditionID : ' + Style.RESET_ALL + Edition_ID)
    PowerShellScript.write("\nEditionID : " + Edition_ID)
    print(Fore.CYAN + 'ReleaseID : ' + Style.RESET_ALL + Release_ID)
    PowerShellScript.write("\nReleaseID : " + Release_ID)
    print(Fore.CYAN + 'BuildBranch : ' + Style.RESET_ALL + Branch)
    PowerShellScript.write("\nBuildBranch : " + Branch)
    print(Fore.CYAN + 'CurrentMajorVersionNumber : ' + Style.RESET_ALL + str(CurrentMajorVersionNumber))
    PowerShellScript.write("\nCurrentMajorVersionNumber : " + str(CurrentMajorVersionNumber))
    print(Fore.CYAN + 'Current_Version : ' + Style.RESET_ALL + str(Current_Version))
    PowerShellScript.write("\nCurrent_Version : " + str(Current_Version))
    if is_admin == False:
        print(Fore.CYAN + 'Process Running As Admin : ' + Style.RESET_ALL + str(is_admin))
        PowerShellScript.write("\nProcess Running As Admin : " + str(is_admin))
    else:
        print(Fore.CYAN + 'Process Running As Admin : ' + Style.RESET_ALL + Fore.RED + str(is_admin) + Style.RESET_ALL)
        PowerShellScript.write("\nProcess Running As Admin : " + str(is_admin))
    if is_VM == False:
        print(Fore.CYAN + 'Within A Virtual Machine : ' + Style.RESET_ALL + str(is_VM))
        PowerShellScript.write("\nWithin A Virtual Machine : " + str(is_VM))
    else:
        print(Fore.CYAN + 'Within A Virtual Machine : ' + Style.RESET_ALL + Fore.RED + str(is_VM) + Style.RESET_ALL)
        PowerShellScript.write("\nWithin A Virtual Machine : " + str(is_VM))
        
##TODO FIX COMMAND LINE ARGUMENTS SPECIFICALLY FILE PATH
def Parse_Arguments():
    Valid_Short_Options = ['-S','-L','-U','-N','-P','-E','-A','-D','-W']
    Valid_Long_Options = ['--SystemInfo','--Logging','--UserPrivileges','--Network','--Processes','--Services','--Applications','--Services','--PathDLL','--WindowsCredentials','--FileOutput']
    # We can specify long|short options for arguments the GUI mainly calls using short options becuase it's less characters
    #We have a bunch of options that do nothing and are left in too show expansion
    parse = argparse.ArgumentParser()
    options = parse.add_mutually_exclusive_group(required=True) #This means that enviroment variables are mutually exclusing i.e -S cant be with -L 
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
    arguments = parse.parse_args() #Gets all the values from the arguments passed in the function
    #Really dumb way to make sure that the output path is valid this is mainly for CLI usage GUI performs its own authentication on files.
    ArgumentsProvided = False
    while ArgumentsProvided == False:
        SplitPath = arguments.FileOutput.rsplit('\\',1)[0]
        if '\\' not in SplitPath:
            SplitPath = '.\\' 
        OutputPath = Path(SplitPath.strip())
        if OutputPath.exists() == False:
            print('You must provide a valid output path')
            arguments.FileOutput = input('Please enter a valid output path : \n')
        else:
            ArgumentsProvided = True
    return arguments

if __name__ == '__main__':
    #Here we only get systeminfo but we can expand greatly and do a load of stuff more. I didnt realise how much stuff was in one section
    arguments = Parse_Arguments()
    if arguments.SystemInfo == True:
        SystemInfo(arguments.FileOutput)
        print("CREATED_FILE")

    
