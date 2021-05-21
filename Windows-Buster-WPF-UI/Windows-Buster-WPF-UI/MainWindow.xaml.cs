﻿using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Windows_Buster_WPF_UI
{
    class Program
    {
        public bool CheckValidDirectory(string FilePath)
        {
            int index = FilePath.LastIndexOf(@"\");
            string Path = FilePath.Substring(0,index + 1);
            Debug.WriteLine(Path);
            bool ValidFilePath = Directory.Exists(Path);
            return ValidFilePath;
        }
        public bool CheckValidFile(string FilePath)
        {
            bool ValidFile = File.Exists(FilePath);
            return ValidFile;
        }
    }
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private string DisplayCheck(string file, string start_delim, string end_delim,string result)
        {
            string line;
            System.IO.StreamReader reader = new System.IO.StreamReader(@file);
            while ((line = reader.ReadLine()) != start_delim)
            {
            }
            result += line + "\n";
            while ((line = reader.ReadLine()) != end_delim)
            {
                result += line + "\n";
            }
            result += "\n\n";
            Debug.WriteLine(result);
            return result;
        }
        private void DisplaySystemInformation_Click(object sender, RoutedEventArgs e)
        {
            if (ValidPathLabel.Content != "Valid Path : True")
            {
                RanCLILabel.Content = "PATH FILE IS INVALID";
                RanCLILabel.Foreground = new SolidColorBrush(Colors.Red);
            }
            else
            {
                //SOURCE: https://betterprogramming.pub/running-python-script-from-c-and-working-with-the-results-843e68d230e5
                ProcessStartInfo start = new ProcessStartInfo();
                start.FileName = "C:\\Python39\\python.exe"; //This could probably done better this points to the python.exe on my system i assume its the same on yours :/
                string cmd = "C:\\Users\\jackh\\Documents\\Andrews-Coding\\Windows-Buster-PLCS\\CLI-PS.py";
                string RawFilePath = (string)InputtedPathLabel.Content;
                string RefineFilePath = RawFilePath.Substring(RawFilePath.IndexOf(':') + 1);
                string FileArgument = "-F" + RefineFilePath;
                FileArgument = FileArgument.Trim();
                string OptionArgument = "-S";
                start.Arguments = $"\"{cmd}\" \"{FileArgument}\" \"{OptionArgument}\"";
                Debug.WriteLine($"\"{cmd}\" \"{FileArgument}\" \"{OptionArgument}\"");
                start.UseShellExecute = false;
                start.RedirectStandardOutput = false;
                start.RedirectStandardError = false;
                using (Process process = Process.Start(start))
                {
                }
                RanCLILabel.Content = "OUTPUT FILE GENERATED IN: " + RefineFilePath;
                RanCLILabel.Foreground = new SolidColorBrush(Colors.Green);
            }
        }
        private void cbSelectAll_Checked(object sender, RoutedEventArgs e)
        {
            //If the value of the select all checkbox is true turn all checkboxes to true no matter if they are false or true
            bool CheckVal = (cbSelectAll.IsChecked == true);
            cbSystemInformation.IsChecked = CheckVal;
            cbMicrosoftUpdates.IsChecked = CheckVal;
            cbPSSettings.IsChecked = CheckVal;
            cbLSAProtection.IsChecked = CheckVal;
            cbCredentialGuard.IsChecked = CheckVal;
            cbWDigest.IsChecked = CheckVal;
            cbCachedCreds.IsChecked = CheckVal;
            cbEnviromentVariables.IsChecked = CheckVal;
            cbInternetSettings.IsChecked = CheckVal;
            cbCurrentDrives.IsChecked = CheckVal;
            cbAVInformation.IsChecked = CheckVal;
            cbUACConfiguration.IsChecked = CheckVal;
            cbNTLMSettings.IsChecked = CheckVal;
            cbPrinters.IsChecked = CheckVal;
            cbNetVersions.IsChecked = CheckVal;
        }
        private void LoadFileOption_Click(object sender, RoutedEventArgs e)
        {
            string FilePath;
            FilePath = InputFileOption.Text;
            InputtedPathLabel.Content = $"Inputted Path: {FilePath.ToString()}";
            Program p = new Program();
            bool ValidDirectory = p.CheckValidDirectory(FilePath);
            bool endsInTxt = FilePath.EndsWith(".txt");
            if (endsInTxt == true && ValidDirectory == true)
            {
                ValidPathLabel.Content = "Valid Path : True";
                ValidPathLabel.Foreground = new SolidColorBrush(Colors.Green);
            }
            else
            {
                if (endsInTxt == false)
                {
                    ValidPathLabel.Content = "Valid Path : False - File Does Not End In .txt";
                    ValidPathLabel.Foreground = new SolidColorBrush(Colors.Red);
                }
                else
                {
                    ValidPathLabel.Content = "Valid Path : False - Directory Could Not Be Found";
                    ValidPathLabel.Foreground = new SolidColorBrush(Colors.Red);
                }
            }
        }
        private void DisplayInformation_Click(object sender, RoutedEventArgs e)
        {
            Program p = new Program();
            string file;
            string result = "";
            string RawDefaultFilePath = InputFileOption.Text;
            bool endsInTxt = RawDefaultFilePath.EndsWith(".txt");
            bool ValidFile = p.CheckValidFile(RawDefaultFilePath);
            bool Valid_Default;
            bool Valid_Optional;
            if (endsInTxt == true && ValidFile == true)
            {
                Valid_Default = true;

            }
            else
            {
                Valid_Default = false;
            }
            if (ValidOptionalFile.Content != "Valid File : True")
            {
                Valid_Optional = false;
            }
            else
            {
                Valid_Optional = true;
            }
            if (Valid_Default == true || Valid_Optional == true)
            {
                if (Valid_Optional)
                {
                    file = OptionalChosenFile.Text;
                    DisplayCanBeRan.Content = "Running Using Provided File";
                    DisplayCanBeRan.Foreground = new SolidColorBrush(Colors.Green);
                }
                else
                {
                    file = RawDefaultFilePath;
                    DisplayCanBeRan.Content = "Running Previously Created File";
                    DisplayCanBeRan.Foreground = new SolidColorBrush(Colors.Green);
                }
                if (cbSystemInformation.IsChecked == true)
                {
                    result = DisplayCheck(file, "BASIC OS INFORMATION [*]", "FOUND UPDATES [*]", result);
                }
                if (cbMicrosoftUpdates.IsChecked == true)
                {
                    result = DisplayCheck(file, "FOUND UPDATES [*]", "ENVIRONMENT VARIABLES [*]", result);
                }
                if (cbPSSettings.IsChecked == true)
                {
                    result = DisplayCheck(file, "POWERSHELL SETTINGS [*]", "LSA PROTECTION/SETTINGS [*]", result);
                }
                if (cbLSAProtection.IsChecked == true)
                {
                    result = DisplayCheck(file, "LSA PROTECTION/SETTINGS [*]", "CREDENTIAL GUARD [*]", result);
                }
                if (cbCredentialGuard.IsChecked == true)
                {
                    result = DisplayCheck(file,"CREDENTIAL GUARD [*]", "WDIGEST SETTINGS [*]", result);
                }
                if (cbWDigest.IsChecked == true)
                {
                    result = DisplayCheck(file, "WDIGEST SETTINGS [*]", "NUMBER OF CACHED CREDENTIALS [*]", result);
                }
                if (cbCachedCreds.IsChecked == true)
                {
                    result = DisplayCheck(file, "NUMBER OF CACHED CREDENTIALS [*]", "USER INTERNET SETTINGS [*]", result);
                }
                if (cbEnviromentVariables.IsChecked == true)
                {
                    result = DisplayCheck(file, "ENVIRONMENT VARIABLES [*]", "POWERSHELL SETTINGS [*]", result);
                }
                if (cbInternetSettings.IsChecked == true)
                {
                    result = DisplayCheck(file, "USER INTERNET SETTINGS [*]", "ANTI-VIRUS INFORMATION [*]", result);
                }
                if (cbCurrentDrives.IsChecked == true)
                {
                    result = DisplayCheck(file, "DRIVES INFORMATION [*]", "UAC CONFIGURATION [*]", result);
                }
                if (cbAVInformation.IsChecked == true)
                {
                    result = DisplayCheck(file, "ANTI-VIRUS INFORMATION [*]", "DRIVES INFORMATION [*]", result);
                }
                if (cbUACConfiguration.IsChecked == true)
                {
                    result = DisplayCheck(file, "UAC CONFIGURATION [*]", "ENUMERATING NTLM SETTINGS [*]", result);
                }
                if (cbNTLMSettings.IsChecked == true)
                {
                    result = DisplayCheck(file, "ENUMERATING NTLM SETTINGS [*]", "PRINTER INFORMATION [*]", result);
                }
                if (cbPrinters.IsChecked == true)
                {
                    result = DisplayCheck(file, "PRINTER INFORMATION [*]", "CLR & .NET VERSIONS [*]", result);
                }
                if (cbNetVersions.IsChecked == true)
                {
                    result = DisplayCheck(file,"CLR & .NET VERSIONS [*]", null, result);
                }
                DisplaySettingText.Text = result;
            }
            else
            {
                DisplayCanBeRan.Content = "Cannot Be Ran - No Default & No Optional";
                DisplayCanBeRan.Foreground = new SolidColorBrush(Colors.Red);
            }
        }
        private void LoadChosenFile_Click(object sender, RoutedEventArgs e)
        {
            Program p = new Program();
            string FilePath = OptionalChosenFile.Text;
            bool ValidFile = p.CheckValidFile(FilePath);
            bool endsInTxt = FilePath.EndsWith(".txt");
            if (ValidFile == true && endsInTxt == true)
            {
                ValidOptionalFile.Content = "Valid File : True";
                ValidOptionalFile.Foreground = new SolidColorBrush(Colors.Green);
            }
            else
            {
                if (endsInTxt == false)
                {
                    ValidOptionalFile.Content = "Valid File : False - File Does Not End in .txt";
                    ValidOptionalFile.Foreground = new SolidColorBrush(Colors.Red);
                }
                else
                {
                    ValidOptionalFile.Content = "Valid File : False - File Could Not Be Found Check Inputted Directory";
                    ValidOptionalFile.Foreground = new SolidColorBrush(Colors.Red);
                }
            }
        }
    }
}
