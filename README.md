# About
- Palware is a threat finder wich :
    - Finds and alert/block malicious files like Shellers , Backdoors and etc.
    - Monitors all executed commands then find and alert malicious commands (like reading passwd)
    - Finds and alert/block SQLI & XSS testing on website
    - Block IP adresses Manually
    - Block attacker(s) IP(s) automatically

# Note 
- For Sending email attention , you must turn on "Access for less secure apps" on your sender gmail : [HERE](https://www.google.com/settings/u/1/security/lesssecureapps) 

# How-To
- Run palware.sh with root. otherwise, script wont work properly .
    - ``` sudo chmod +x palware.sh;./palware.sh ```
- To update your app manually : 
    - Remove installed.txt from "inc" folder
    - Run palware.sh with root

# Comming Soon ...
- Support ReadHat based distro's
- Application automatic update
- Recognize POST method SQL/XSS attacks
- Add more patterns for executed commands 

# Contact Me 
- Help Me To Improve : SeedPuller@gmail.com