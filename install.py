import os
import sys
import subprocess
if os.path.exists("inc/installed.txt"):
    sys.exit(1)
colors = {"green": "\033[32m", "normal": "\033[m", "red": "\033[31m", "white": "\033[37m", "orange": "\033[33m"}
print(" {0}.::: Palware Installation :::. {1}\n".format(colors["orange"], colors["normal"]))


def bashexec(command):  # executing bash commands and Do Not return that outputs
        process = subprocess.getstatusoutput(command)
        if process[0] == 0:
            return True
        else:
            return False


print("{0} [!] Installing Requirements ... \n {1}".format(colors["orange"], colors["normal"]))

if not bashexec("sudo apt install inotify-tools"):
    print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
    sys.exit(1)

if not bashexec("sudo apt install auditd"):
    print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
    sys.exit(1)

print("{0} Script installed and configured successfully !".format(colors["red"]))

# editing auditd configuration file.

auditconf = open("inc/audit.conf", "r").read()
auditconfedit = open("/etc/audit/audit.rules", "w").write(auditconf)

open("inc/installed.txt","w").write("OK")
# installing python3 mysql

# print("{0} [!] Installing python mysql database ... \n {1}".format(colors["orange"], colors["normal"]))
# if not bashexec("sudo apt install python3-mysql.connector"):
#     print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
#     sys.exit(1)
#
# dbname = input(" Please enter your database name : \n --> {0} ".format(colors["red"]))
# dbuser = input(" {0} Please enter your database username : \n --> {1} ".format(colors["normal"], colors["red"]))
# dbpass = input(" {0} Please enter your database password : \n --> {1} ".format(colors["normal"], colors["red"]))
#
# db = Modules.Db.predb(dbuser, dbpass, dbname) # connecting to database
#
# if db:
#
#     print(" {0}[!] Installing Scanner requirments ... {1}\n".format(colors["orange"], colors["normal"]))
#     if not bashexec("sudo apt install auditd"):
#         print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
#         sys.exit(1)
#     if not bashexec("sudo apt install inotify-tools"):
#         print("{0} [!] Installing faild ! Please check your internet connection !".format(colors["red"]))
#         sys.exit(1)
#     # editing auditd configuration file.
#     auditconf = open("inc/audit.conf", "r").read()
#     auditconfedit = open("/etc/audit/audit.rules", "w").write(auditconf)
#
#     # configuring database
#     databasedata = open("inc/database.sql", "r").read()
#     if db.query(databasedata, 0):
#         createconf = open("inc/config.conf", "w")
#         createconf.write("dbname:{0}\ndbuser:{1}\ndbpass{2}".format(dbname, dbuser, dbpass))
#         print("{0} Script installed and configured successfully !".format(colors["red"]))
# else:
#     print("{0} Database connection faild ! Please check your inputs .".format(colors["red"]))
