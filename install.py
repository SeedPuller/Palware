import os
import sys
import subprocess
import re
if os.path.exists("inc/installed.txt"):
    sys.exit(1)
colors = {"green": "\033[32m", "normal": "\033[m", "red": "\033[31m", "white": "\033[37m", "orange": "\033[33m"}
print(" {0}.::: Palware Installation :::. {1}\n".format(colors["orange"], colors["normal"]))


def bashexec(bashc):  # executing bash commands and return that outputs
    basherr = r"(\/bin\/sh: [0-9]*: [a-zA-Z0-9 !@#$%^&*()\[\]{}\-=+<>\/?.,:;'\"\\|_]*: not found)"
    bash = subprocess.getoutput(bashc)
    if re.search(basherr, bash, re.IGNORECASE):  # check error existence
        return False
    else:
        return True


inotify = "sudo apt install inotify-tools -y"
print("{0} [!] Installing Requirements ... \n {1}".format(colors["orange"], colors["normal"]))

if not bashexec(inotify):
    print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
    sys.exit(1)

print("{0} 1 from 2 requirements installed successfully {1}".format(colors["green"], colors["normal"]))
auditd = "sudo apt install auditd -y"
if not bashexec(auditd):
    print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
    sys.exit(1)
print("{0} 2 from 2 requirements installed successfully {1}".format(colors["green"], colors["normal"]))


# editing auditd configuration file.

auditconf = open("inc/audit.conf", "r").read()
auditconfedit = open("/etc/audit/audit.rules", "w").write(auditconf)

print("{0} [!] Finishing ... \n {1}".format(colors["orange"], colors["normal"]))
if not os.path.exists("/var/log/palware"):
    if not os.mkdir("/var/log/palware"):
        print("{0} [!] Installing faild ! Please try again !".format(colors["red"]))
        sys.exit(1)
apacheconfre = r"(customlog [\s\S]+ combined)"
apachenormconf = open("/etc/apache2/sites-available/000-default.conf", "r").read()
apachesslconf = open("/etc/apache2/sites-available/default-ssl.conf", "r").read()
apachenormconf = re.sub(apacheconfre, " CustomLog ${APACHE_LOG_DIR}/access.log combined\n           CustomLog /var/log/palware/apache2.log combined", apachenormconf,flags=re.IGNORECASE)
open("/etc/apache2/sites-available/000-default.conf", "w").write(apachenormconf)
apachesslconf = re.sub(apacheconfre, " CustomLog ${APACHE_LOG_DIR}/access.log combined\n            CustomLog /var/log/palware/apache2.log combined", apachesslconf,flags=re.IGNORECASE)
open("/etc/apache2/sites-available/default-ssl.conf", "w").write(apachesslconf)

if not os.path.exists("/etc/apache2/palwareconf"):
    os.mkdir("/etc/apache2/palwareconf")

if not bashexec("sudo service apache2 restart"):
    print("{0} [!] Installing faild ! Make sure you have installed apache or you have started this app with root perm !".format(colors["red"]))
    sys.exit(1)
open("inc/installed.txt","w").write("OK")
print("{0} Script installed and configured successfully !\n\n\n".format(colors["green"]))
