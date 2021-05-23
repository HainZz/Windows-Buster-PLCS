import argparse
import requests
import csv
import openpyxl
import os
import msrc
from datetime import datetime
import re
import chardet
from pathlib import Path

#BASED ON: https://github.com/bitsadmin/wesng/blob/19cdaa9f287029695d68697b49ad0d8b04312f6a/wes.py

#SOURCE: https://github.com/haginara/msrc-python/blob/34a038a30f746f1e3a16eb5a04c1002d22e0d75e/msrc.py#L129
def msrCSV(MSRC_File_Path):
    LinesToWrite=[]
    #Get all monthly releases
    update_request = requests.get(f"https://api.msrc.microsoft.com/Updates",headers={"Accept":"application/json"},params={"api-version": datetime.now().year})
    data = update_request.json()
    values = data["value"]
    for value in values:
        crvf_id = value['ID']
        url = f"https://api.msrc.microsoft.com/cvrf/" + crvf_id
        cvrf_request = requests.get(url,headers={"Accept":"application/json"},params={"api-version": datetime.now().year})
        data = cvrf_request.json()
        if 'Vulnerability' in data:
            #Enumerate over every CVE's per monthly release
            for vuln in data['Vulnerability']:
                #Enumerate over KB's per CVE
                for kb in vuln['Remediations']:
                    if 'ProductID' in kb:
                        for productid in kb['ProductID']:
                            CSVLine = []
                            UnConvertedDate = vuln['RevisionHistory'][-1]['Date']
                            UnConvertedDate = UnConvertedDate.replace("T"," ")
                            CovertedDate = UnConvertedDate.replace("Z","")
                            BulletinKB = kb['Description']['Value']
                            for threat in vuln['Threats']:
                                if 'ProductID' in threat:  
                                    if productid in threat['ProductID']:
                                        if threat['Type'] == 3: #Types seem to specify there description i.e type 3 seems to be severity description type 0 impact
                                            Severity = threat['Description'].get('Value')
                                        elif threat['Type'] == 0:
                                            Impact = threat['Description'].get('Value')
                            Title = vuln['Title'].get('Value')
                            for product in data['ProductTree']['FullProductName']:
                                if product['ProductID'] == productid:
                                    Product_Index = data['ProductTree']['FullProductName'].index(product)
                                    Affected_Product = data['ProductTree']['FullProductName'][Product_Index]['Value']
                            Affected_Component = vuln['Notes'][-1]['Title']
                            Supersedes= kb.get('Supercedence')
                            try:
                                Supersedes = Supersedes.replace(',',';').strip()
                                Supersedes = Supersedes.replace(" ","")
                            except AttributeError:
                                pass
                            CVE = vuln['CVE']
                            CSVLine.append(CovertedDate) #0
                            CSVLine.append(BulletinKB) #1
                            CSVLine.append(Severity) #2 
                            CSVLine.append(Impact) #3
                            CSVLine.append(Title)
                            CSVLine.append(Affected_Product)
                            CSVLine.append(Affected_Component)
                            CSVLine.append(Supersedes)
                            CSVLine.append(CVE)
                            LinesToWrite.append(CSVLine)
    with open(MSRC_File_Path.lstrip(),'w',newline="") as msrc:
        writer = csv.writer(msrc,delimiter=',',quotechar='"',quoting=csv.QUOTE_MINIMAL)
        for line in LinesToWrite:
            writer.writerow(line)
            #print(line)
            msrc.flush()
    msrc.close()

##SOURCE: https://www.gaijin.at/en/infos/windows-version-numbers
def determine_version_build(Build_Number,Server):
    builds = {
        '10240':'Windows 10 Version 1507',
        '10586':'Windows 10 Version 1511',
        '14393':['Windows 10 Version 1607','Windows Server 2016'],
        '15063':'Windows 10 Version 1703',
        '16299':['Windows 10 Version 1709','Windows Server 2016'],
        '17134':'Windows 10 Version 1803',
        '17763':['Windows 10 Version 1809','Windows Server 2019'],
        '18362':'Windows 10 Version 1903',
        '18363':'Windows 10 Version 1909',
        '19041':'Windows 10 Version 2004',
        '19042':'Windows 10 Version 20H2'
    }
    Version_Number = builds.get(Build_Number)
    if isinstance(Version_Number, list):
        if Server == True:
            Version_Number = Version_Number[1]
        else:
            Version_Number = Version_Number[0]
    return Version_Number

##SOURCE : https://stackoverflow.com/questions/436220/how-to-determine-the-encoding-of-text
def DecodeFile(InFile):
    File = open(InFile.lstrip(),'rb').read()
    encoding_type = chardet.detect(File)
    File = File.decode(encoding_type['encoding'],'ignore')
    return File


def search(InputFile,CSVFile):
    system_info_data = DecodeFile(InputFile)
    OS_NAME = (system_info_data.split('OS Name:'))[1].split('OS Version:')[0].strip()
    OS_VERSION = (system_info_data.split('OS Version:'))[1].split('OS Manufacturer:')[0].strip()
    SYSTEM_TYPE = (system_info_data.split('System Type:'))[1].split('Processor(s):')[0].strip()
    arch = SYSTEM_TYPE.split('-')[0]
    hotfixes = re.findall('.*KB\d+.*', system_info_data)
    Stripped_Hotfix = []
    for hotfix in hotfixes:
        Stripped_Hotfix.append(re.search('.*KB(\d+).*', hotfix).group(1))
    OS_Version_array = []
    for x in OS_VERSION.split():
        if x != 'Service' and x != 'Pack' and x !='Build':
            OS_Version_array.append(x)
    if 'Server' in OS_NAME:
        Server = True
    else:
        Server = False
    Windows10_Version = determine_version_build(OS_Version_array[2],Server)
    if arch == "x86":
        arch = '32-bit'
    elif arch == "x64":
        arch = 'x64-based'
    Windows10_Version = Windows10_Version + " for " + arch + " Systems"
    ##CURRENTLY IM ONLY SUPPORTING WINDOWS 10 FOR TESTING THIS IS AN KEY AREA OF EXPANSION TO WRITE ABOUT IN DOCUMENTATION
    Found_Vulns = Find_Potential_Vulns(Windows10_Version, Stripped_Hotfix,CSVFile)

def get_superseeded_hotfixes(Found_Vulns,hotfix,marked): ##This function is pretty much stolen from WES.py as i couldnt figure out what to with the superseeded values myself
    for super_seeded_item in hotfix.split(';'):
        TempArray = filter(lambda vuln: vuln[9] and vuln[1] == super_seeded_item, Found_Vulns)
        for ss in TempArray:
            ss[9] = False
            if ss[7] and ss[7] not in marked:
                marked.add(ss[7])
                get_superseeded_hotfixes(Found_Vulns,ss[7],marked)
    
def Find_Potential_Vulns(Windows10_Version,Stripped_Hotfix,MSRC_File_Path):
    Found_Vulns = []
    with open (MSRC_File_Path.lstrip()) as MSRC_CSV:
        csv_reader = csv.reader(MSRC_CSV,delimiter=',')
        for row in csv_reader:
            if row[5] == Windows10_Version: #FIND CVE's that correspond with our product. We dont wanna find vulns for windows 7 when the system info file is for windows 10
                if row[7]:
                    Stripped_Hotfix.append(row[7]) #Add the superseeded KB to our hotfixes
                row.append(True)
                Found_Vulns.append(row)
    Stripped_Hotfix = list(set(Stripped_Hotfix)) #Remove all produced duplicate hotfixes
    marked = set()
    for hotfix in Stripped_Hotfix:
        get_superseeded_hotfixes(Found_Vulns,hotfix,marked)
    check = filter(lambda cve: cve[9],Found_Vulns)
    supersedes = set([x[7] for x in check])
    checked = filter(lambda cve: cve[1] in supersedes,check)
    for vuln in checked:
        vuln[9] = False
    Found_Vulns = list(filter(lambda cve: cve[9],Found_Vulns))
    print("FOUND VULNS NOTE: THEY'RE MAY BE FALSE POSITIVES OR STUFF THAT SHOULDNT COME UP DUE TO THE DATASET [*]")
    for maybe_vuln in Found_Vulns:
        print("CVE: " + maybe_vuln[8])
        print("KB: " + maybe_vuln[1])
        print("Title: " + maybe_vuln[4])
        print("Impact: " + maybe_vuln[3])
        print("Severity: " + maybe_vuln[2])
        print("Affected Component: " + maybe_vuln[6])
        print("Affected Product: " + maybe_vuln[5])
        print("\n")

def Parse_Arguments():
    ##COMMAND LINE ARGUMENTS for WES.py
    Valid_Short_Options = ['-M','-F','-S','-C']
    Valid_Long_Options = ['--msrc','--search','--file','--msrcfile']
    parse = argparse.ArgumentParser()
    options = parse.add_mutually_exclusive_group(required=True)
    options.add_argument('-M','--msrc',action='store_true',help='Updates the MSRC CSV Located in the WES-CSV Folder')
    options.add_argument('-S','--search',action='store_true',help='Searches avaliable CSV files for missing patches & potential vulns')
    parse.add_argument('-F','--file',help='Specify systeminfo.txt file at this location will program will exit if none is found when searching')
    parse.add_argument('-C','--msrcfile',help='Specify MSRC CSV Location make sure path is abosolute',required=True)
    arguments = parse.parse_args()
    if arguments.msrc == True:
        ArgumentsProvided = False
        while ArgumentsProvided == False:
            SplitPath = arguments.msrcfile.rsplit('\\',1)[0]
            if '\\' not in SplitPath:
                SplitPath = '.\\' 
            OutputPath = Path(SplitPath.strip())
            if OutputPath.exists() == False:
                print('You must provide a valid output path')
                exit(1)
            else:
                if arguments.msrcfile.endswith('.csv'):
                    ArgumentsProvided = True
                else:
                    print("You must enter a valid file extension i.e .csv")
                    exit(1)
    else:
        if (os.path.isfile(arguments.msrcfile.lstrip())):
            if arguments.msrcfile.endswith('.csv'):
                pass
            else:
                print("You must enter a valid file extension i.e .csv")
                exit(1)
        else:
            print(os.path.isfile(arguments.msrcfile))
            print("INVALID MSRC FILE OPTION ENTERED PLEASE TRY AGAIN")
            exit(1)
    if arguments.file != None:
        if (os.path.isfile(arguments.file.lstrip())):
            if arguments.file.endswith('.txt'):
                pass
            else:
                print("INVALID SYSTEM INFO FILE MUST BE OF EXTENSION .txt")
                exit(1)
        else:
            print("INVALID SYSTEM FILE OPTION ENTERED PLEASE TRY AGAIN")
            exit(1)
    return arguments

if __name__ == '__main__':
    #Check arguments run found arguments. Run Update's first if specified then do the Vuln check
    arguments = Parse_Arguments()
    if arguments.msrc == True:
        msrCSV(arguments.msrcfile)
        print("CREATED_FILE")
    if arguments.search == True:
        search(arguments.file,arguments.msrcfile)
