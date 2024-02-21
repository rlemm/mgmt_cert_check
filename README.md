# ![alt text](https://github.com/rlemm/mgmt_cert_check/blob/main/palo.ico) cert-mgmt-check
This tool empowers you to effortlessly determine whether or not you are affected on your PANOS Firewalls and Panorama devices. The primary objective is to ensure that your devices operate on a PAN-OS version unaffected by the expiration of the management certificate on April 7th, 2024.  For further details, please refer to these links below:

### [Management Certificate Expiration on April 7th, 2024](https://live.paloaltonetworks.com/t5/customer-advisories/additional-pan-os-certificate-expirations-and-new-comprehensive/ta-p/572158)

Before we dive in, let's go over the prerequisites for using this tool. First, make sure you're running Python version 3.x or greater on the host you will be using to run this tool. Second, create a text file containing the IP addresses of your Panorama devices. Save this file in the same location where you'll run the Self Impact Discovery Tool.  Below is an Example:

```
192.168.1.1
10.1.1.1
172.16.1.1
```

Any text editor will do as long as you save it in basic text format.  If there are any errors in the file, (ie extra carriage returns, invalid IP's) the tool will tell you and skip them.  Do not use FQDN's.  IP Addresses only.

## Step 1:

Download the tool from this site by clicking on the Green Button in the Upper Right-Hand corner labeled "Code." Next, click on "Download ZIP." This action will download everything you need to proceed to the following steps.

https://github.com/rlemm/mgmt_cert_check

## Step 2:

Once downloaded to a folder of your choice, extract the file into that folder. Open a terminal window or CLI on your platform, navigate to the folder where you extracted the tool, and run the following command:

```console
pip3 install -r requirements.txt
```
## or

```console
pip install -r requirements.txt
```

## Note for Decryption:

Please use the tool on a host that traffic will not be decrypted between itself and the Panorama Devices

## Note for Windows Users:

If you are running Microsoft Windows 10, you may need to run the following commands as well:

```console
python3 -m pip install --upgrade --user urllib3
python3 -m pip install
```
## or
```console
python -m pip install --upgrade --user urllib3
python -m pip install
```
## Step 3

After installing the requirements, type the following command:
```console
python3 mgmt_cert_check.py

```

## Step 4

Run the following command. If you wish to use any of the argument options mentioned earlier, please add those to your command:

```
python3 mgmt_cert_check.py
```
## or
```
python mgmt_cert_check.py
```
You'll be prompted to enter the name of the text file you created earlier and your credentials. Ensure you use credentials with API access rights. MFA credentials will not work with this tool. Use a common local service account; superuser rights are not necessary—readonly-superuser will work.

Once the tool finishes running, you'll see results with different colors. Green indicates no action is needed, yellow means action is required based on the scenarios explained in the links on this GitRepo, and red means both actions need to be taken.
