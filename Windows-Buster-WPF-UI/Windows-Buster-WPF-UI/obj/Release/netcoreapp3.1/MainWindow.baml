   M S B A M L   `   `   `  ���� P  LWindows-Buster-WPF-UI, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null=#clr-namespace:Windows_Buster_WPF_UIWindows_Buster_WPF_UI  &     Windows_Buster_WPF_UI.MainWindow   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5local#clr-namespace:Windows_Buster_WPF_UI       � Title$  Windows-Buster-PLCS��$	��750��$	��750��.��� .+��� .@��� $��View-Windows-Information��.���� .@��� $��View-System-Information��.���� .���� .+�� .+��� -    ��Name$ DisplaySystemInformation��$	��250��$��50��.��Get System Information�� -    ��Name$ RanCLILabel��$�� ��� .+��� -   $ LoadFileOption��$	��250��$��20��.��Input Output File�� -    ��Name$ InputFileOption��$	��470��$��20���� .��A?Help: Directory For File Must Be Valid, File-Name must end .txt�� -   $ InputtedPathLabel��$��Inputted Path:���� -   $ ValidPathLabel��$
��Bold"�$��Valid Path:���� $
��Bold"�$!��System Information Options:���� -    ��Name$ cbSelectAll�� d� IsThreeState$
 True��.��
Select All�� -   $ cbSystemInformation��.��Basic System Information�� -	   $ cbMicrosoftUpdates��.��Enable Microsoft Updates�� -
   $ cbPSSettings��.��PS Settings�� -   $ cbLSAProtection��.��LSA Protection�� -   $ cbCredentialGuard��.��Credential Guard�� -   $ 	cbWDigest��.��	WDigest�� -   $ cbCachedCreds��.��No OF Cached Creds�� -   $ cbEnviromentVariables��.��Enviroment Variables�� -   $ cbInternetSettings��.��Internet Settings�� -   $ cbCurrentDrives��.��Current Drives Information�� -   $ cbAVInformation��.��AV Information�� -   $ cbUACConfiguration��.��UAC Configuration�� -   $ cbNTLMSettings��.��NTLM Settings�� -   $ 
cbPrinters��.��
Printers�� -   $ cbNetVersions��.��.NET Versions� .+��� -   $ LoadChosenFile��$	��250��$��20��.��Optional Chosen File�� -   $ ValidOptionalFile��$�� ���� -   $ OptionalChosenFile��$	��470��$��20���� -   $ DisplayInformation��$	��250��$��50��$��Display Information���� -   $ DisplayCanBeRan��$�� ���� -   $ DisplaySettingText�� �� 
IsReadOnly$
 True��$
��Auto=�$
��Auto=�$
��True�� �� TextWrapping$
 Wrap=�.���� $��View-UserInformation��.��� �� $��Windows Vuln Suggester��.���� .���� .+�� .+��� -   $ UpdateMSRCcsv��$	��250��$��50��.��Update MSRC CSV�� -   $ UpdateStatus��$�� ���� $
��Bold"�.��Enter MSRC File Path:�� -   $ MSRCFileOption��$	��470��$��20��� .+��� -    $ GetVulns��$	��250��$��50��.��-+Display Vulns Based Off systeminfo.txt file�� -!   $ GetVulnStatus��$�� ���� $
��Bold"�.��Enter MSRC CSV File Path:�� -"   $ VulnMSRCFileOption��$	��470��$��20���� $
��Bold"�.��31Enter System Info File (NOTE: MUST BE WINDOWS 10)�� -#   $ SystemInfoOption��$	��470��$��20���� $
��Bold"�.��Found Vulns:�� -$   $ DisplayVulns��$
 True��$
��Auto=�$
��Auto=�$
��True��$
 Wrap=�.��