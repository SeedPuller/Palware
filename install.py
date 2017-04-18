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
#inotify = ["sudo", "apt", "install", "inotify-tools", "-y"]
print("{0} [!] Installing Requirements ... \n {1}".format(colors["orange"], colors["normal"]))

if not bashexec(inotify):
    print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
    sys.exit(1)

print("{0} 1 from 2 requirements installed successfully {1}".format(colors["green"], colors["normal"]))
auditd = "sudo apt install auditd -y"
#auditd = ["sudo", "apt", "install", "auditd", "-y"]
if not bashexec(auditd):
    print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
    sys.exit(1)


# editing auditd configuration file.

auditconf = open("inc/audit.conf", "r").read()
auditconfedit = open("/etc/audit/audit.rules", "w").write(auditconf)

open("inc/installed.txt","w").write("OK")

print("{0} Script installed and configured successfully !\n\n\n".format(colors["green"]))
