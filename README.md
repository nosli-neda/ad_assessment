# About ad_assessment
ad_sec_ass is a Powershell script for analyzing Active Directory security and generating reports and graphs of those found.

It was created as a play on how to analyze AD security and has evolved.

Many improvements (mainly programming logic) need to be made.

Some security flaws it detects:
  - Number of privileged users (Enterprise Admins, Domain Admins, Administrators);
  - Users/Privileged Users with "Password Never Expires"
  - Users with "AdminCount";
  - Users with "Password not Required" set;
  - Users with "Password Using Reversing Encryption"
  - Users with "Does not Requires PreAuth Kerberus"
  - Users with "SID History"
  - All Domain Controllers;
  - List of Trusts;
  - Possible Kerberoasting Accounts;
  - Date of last password change for the KRBTGT user

# How to use

To run the scan, just run the script ad_sec_assessment.ps1 on a machine authenticated in the domain and wait for completion.

The script will generate 3 files:
 - Assessment_<domain_name>.html
 - Detail_<domain_name>.html
 - Risk_<domain_name>.html

# Samples Images

![Assessment 1](https://raw.githubusercontent.com/nosli-neda/ad_assessment/main/Images/Image1.jpg?raw=true)
<hr>
![Assessment 1](https://raw.githubusercontent.com/nosli-neda/ad_assessment/main/Images/Image2.jpg?raw=true)
![Assessment 1](https://raw.githubusercontent.com/nosli-neda/ad_assessment/main/Images/Image3.jpg?raw=true)
![Assessment 1](https://raw.githubusercontent.com/nosli-neda/ad_assessment/main/Images/Image4.jpg?raw=true)
