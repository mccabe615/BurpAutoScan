Title of the Project
================
This project contains a Burp Extension and a python script for invoking the extension to perform automated **and**  authenticated scans against all URL's listed in a configuration file. Authentication is accomplished through Burp State files. Optionally, a Nikto scan can be invoked as well.
#Configuration
## Set up Burp
Install Burp (Pro Edition, because scanning is not available with free version)

Download jython standalone jar and point Burp to it on the `Extender-->Options` tab, in the "Python Environment" section.

Install Burp extensions by going to the Extender tab within Burp.
For better scan results,  use the BApp Store tab to install "Active Scan++" and "Additional Scanner Checks".  Make sure that these are listed before the AutoScanWithBurp extension so that they load first.

Install the AutoScanWithBurp extension by selecting "Add" from the `Extender-->Extensions` tab in Burp and selecting an extension type of "Python" then select the provided AutoScanWithBurp.py file as the Extension file.  For Standard Output and Standard Error select "Output to system console"

Ensure that the "Automatically reload extensions on startup" option is checked on the `Extender-->Options` tab.

Close Burp.

## Install Nikto (optional)

Install the Nikto tool if not already installed and take note of the install directory.

https://cirt.net/nikto2-docs/installation.html

Edit the AutoScanWithBurp config.json file to enable the Nikto Scan:

    runNikto = True

## Install Python

The AutoScanWithBurp script is a Python script.  Install Python and take note of the install directory.

https://www.python.org/downloads/

## Configure AutoScanWithBurp

The RunScans.py file must be executable (*nix only, not Windows).  This can be accomplished with the following command:

    $ chmod +x RunScans.py

Locate the provided config.json file and update the fileLocations section to locate the Nikto and Burp exectubles. Set the "reportOutputPath" to **an existing location** where you want the reports from the automated scans to be saved.  Note: a configWindows.json file is also provided as an example of how to set the file locations for Windows but make your changes in the config.json file both both *nix and Windows.

Configure the `burpConfigs-->memory` setting (in config.json) to be about 50% of the available RAM on the machine.  For example, set it to "2048m" to allow Burp to use 2048 megabytes of RAM.

It is anticipated that the Burp scans will be run unattended so the option to run Burp in headless mode (no User Interface) is configured by default.  If you want the UI to be visible while it runs so you can see what is happening, you can set `burpConfigs-->headless` to false.  When the scan completes, the Burp UI will exit.
#Usage
## Run the Script Manually

If you would like to run the script which invokes the Burp extension from the command line . . .

    $ python RunScans.py

## Schedule the Script to Run Automatically (*nix only)

Enter this cron job to run the script every day at 11pm.  The flock command ensures that the cron task will only run one instance of this script at a time.  Remember to update the file paths to match your system.

    0 23 * * * flock -n /var/lock/AutoScanWithBurpLock -c "python /home/yourusername/AutoScanWithBurp/RunScans.py /home/yourusername/AutoScanWithBurp/config.json >> /home/yourusername/AutomatedScans/stdout.txt 2>> /home/yourusername/AutomatedScans/stderr.txt"

Note that this will write script output to stdout.txt and stderr.txt at the locations specified in the above command.


## View The Reports

Burp report is an html file found here: 

`<reportOutputPath>/<dateTimeStamp>_Burp_<protocol>_<fqdn>_<port>.html`

Nikto report is an htm file found here: 

    <reportOutputPath>/<dateTimeStamp>_Nikto_<protocol>_<fqdn>_<port>.htm

 
If you would like to open the Burp State File that was created during the scan for each site, you can find that here:

    <reportOutputPath>/<dateTimeStamp>_BurpState_<protocol>_<fqdn>_<port>

## Sponsors

[![Black Hills Information Security](http://static.wixstatic.com/media/75fce7_d7704144d33847a197598d7731d48770.png_srb_p_287_248_75_22_0.50_1.20_0.00_png_srb)](http://www.blackhillsinfosec.com)


