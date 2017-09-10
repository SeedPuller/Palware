import os
import sys
import subprocess
import re
import platform


if os.path.exists("inc/installed.txt"):
    sys.exit(1)
colors = {"green": "\033[32m", "normal": "\033[m", "red": "\033[31m", "white": "\033[37m", "orange": "\033[33m"}
print(" {0}.::: Palware Installation :::. {1}\n".format(colors["orange"], colors["normal"]))

platf = platform.platform().lower()

configreader = open("inc/palware.conf", "r").readlines()
vhostsname = configreader[1].split(":")[1].split(",")

if "ubuntu" in platf:
    apacheconfpath = "/etc/apache2/"
    inotify = "sudo apt install inotify-tools -y"
    auditd = "sudo apt install auditd -y"
    apachename = "apache2"

    for vpath in vhostsname:
        # opening configs
        apachenormconf = open("{0}/sites-available/{1}".format(apacheconfpath, vpath), "r").read()

        # editing configs and save them .

        open("{0}/sites-available/{1}".format(apacheconfpath, vpath), "w").write(apachenormconf.replace("</VirtualHost>", "      CustomLog /var/log/palware/apache2.log combined\n      ErrorLog /var/log/palware/post.log\n</VirtualHost>"))

else:
    apacheconfpath = "/etc/httpd/conf/"
    inotify = "git clone https://github.com/rvoicilas/inotify-tools/ ; cd inotify-tools ; ./configure ; make ; sudo make install"
    auditd = "sudo yum -y install audit"
    apachename = "httpd"

    for vpath in vhostsname:
        apachenormconf = open("/etc/httpd/conf.d/{0}".format(vpath), "r").read()
        open("/etc/httpd/conf.d/{0}".format(vpath), "w").write(apachenormconf.replace("</VirtualHost>", "      CustomLog /var/log/palware/apache2.log combined\n      ErrorLog /var/log/palware/post.log\n</VirtualHost>"))


def install_inotify():        
    if not bashexec(inotify):
        print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
        sys.exit(1)
        
        
def install_audit():
    if not bashexec(auditd):
        print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
        sys.exit(1)
        
        
def bashexec(bashc):  # executing bash commands and return that outputs
    basherr = r"(\/bin\/sh: [0-9]*: [a-zA-Z0-9 !@#$%^&*()\[\]{}\-=+<>\/?.,:;'\"\\|_]*: not found)"
    bash = subprocess.getoutput(bashc)
    if re.search(basherr, bash, re.IGNORECASE):  # check error existence
        return False
    else:
        return True


print("{0} [!] Installing Requirements ... \n {1}".format(colors["orange"], colors["normal"]))
install_inotify()
print("{0} 1 from 2 requirements installed successfully {1}".format(colors["green"], colors["normal"]))
install_audit()
print("{0} 2 from 2 requirements installed successfully {1}".format(colors["green"], colors["normal"]))


# editing auditd configuration file.

auditconf = open("inc/audit.conf", "r").read()
auditconfedit = open("/etc/audit/audit.rules", "w").write(auditconf)

print("{0} [!] Finishing ... \n {1}".format(colors["orange"], colors["normal"]))
if not os.path.exists("/var/log/palware"):
    if not os.mkdir("/var/log/palware"):
        print("{0} [!] Installing faild ! Please try again ! {1}".format(colors["red"], colors["normal"]))
        sys.exit(1)

#          ## adding necessary options to apache configurations


# creating palware's particular files/folders

if not os.path.exists("{0}/palwareconf".format(apacheconfpath)):
    os.mkdir("{0}/palwareconf".format(apacheconfpath))
if not os.path.exists("{0}/palwareconf/iplist.conf".format(apacheconfpath)):
    open("{0}/palwareconf/iplist.conf".format(apacheconfpath), "w").close()
if not bashexec("sudo service {0} restart".format(apachename)):
    print("{0} [!] Installing faild ! Make sure you have installed apache or you have started this app with root perm !".format(colors["red"]))
    sys.exit(1)

# installing completed

open("inc/installed.txt", "w").write("OK")
print("{0} Script installed and configured successfully !\n\n\n".format(colors["green"]))
