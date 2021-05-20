using System;
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
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private void DisplayInformation_Click(object sender, RoutedEventArgs e)
        {

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
    }
}
