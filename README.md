# About
- Palware is a threat finder wich :
    - Finds and alert/block malicious files like Shellers , Backdoors and etc.
    - Monitors all executed commands then find and alert malicious commands (like reading passwd)
    - Finds and alert/block SQLI & XSS testing on website (even POST requests)
    - Block IP adresses Manually
    - Block attacker(s) IP(s) automatically

# How-To
- Installation
    - Debian Based Distro(s) . (Tested on Ubuntu)
        - Requirements : ``` sudo apt -y install python3 ; sudo apt -y install git ```
        - Then :  ```git clone https://gitlab.com/MadAnt/palware.git ; cd palware ; sudo chmod +x palware.sh;./palware.sh ```
    - RedHat Based Distro(s). (Tested on CentOs)
    - Requirements : ``` sudo yum -y install python3 ; sudo yum -y install gcc make ; sudo yum -y install git ```
    - Then :  ```git clone https://gitlab.com/MadAnt/palware.git ; cd palware ; sudo chmod +x palware.sh;./palware.sh ```


- To update your app manually : 
    - Remove installed.txt from "inc" folder
    - Run palware.sh with root


# Note 
- For Sending email attention , you must turn on "Access for less secure apps" on your sender gmail : [HERE](https://www.google.com/settings/u/1/security/lesssecureapps) 
- Run palware.sh with root. otherwise, script wont work properly .
    - ``` sudo chmod +x palware.sh;./palware.sh ```


# Contact Me 
- Help Me To Improve : SeedPuller@gmail.com