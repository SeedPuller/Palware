import subprocess
import re
import time
import smtplib
import os
import sys
import platform

# setting necessary vars
if not os.path.exists("inc/installed.txt"):
    sys.exit(1)

colors = {"g": "\033[32m", "n": "\033[m", "r": "\033[31m", "w": "\033[37m", "o": "\033[33m"}
print(colors["r"] + open("inc/banner.txt").read() + colors["n"])
print(" %s [+]  Web Threat Finder Version 2.3.1\n\n%s" % (colors["g"], colors["n"]))

# vars
platf = platform.platform().lower()

if "ubuntu" in platf:
    apacheconfpath = "/etc/apache2"
    apachename = "apache2"
else:
    apacheconfpath = "/etc/httpd/conf/"
    apachename = "httpd"

directory = ""
extensions = ""
emailV = False
usern = ""
pasw = ""
dest = ""
maldo = "log"
mal_move_dest = ""
filename = "mal_detect.py"
sqlxss = False
posts = False
attack_do = ""
iplistpath = "{0}/palwareconf/iplist.conf".format(apacheconfpath)
apache2confpath = "{0}/{1}.conf".format(apacheconfpath, apachename)
# defining functions


def saveopt(conf_path):  # saving options in 'conf_path'
    global sqlxss, directory, emailV, usern, pasw, dest, maldo, mal_move_dest, attack_do, posts
    if os.path.isfile(conf_path):
        os.remove(conf_path)  # if option has been exsits , remove it to save new options
    savefile = open(conf_path, "w")
    if savefile.write("directory:{0}\nemailV:{1}\nusern:{2}\npasswd:{3}\ndest:{4}\nmaldo:{5}\nmal_move_dest:{6}\nsqlxss:{7}\nattack_do:{8}\nposts:{9}".format(directory, emailV, usern, pasw, dest, maldo, mal_move_dest, sqlxss, attack_do, posts)):
        return True
    else:
        return False


def loadopt(conf_path):  # load options from 'conf_path'
    global sqlxss, directory, emailV, usern, pasw, dest, maldo, mal_move_dest, attack_do, posts
    if os.path.isfile(conf_path):
        loadfile = open(conf_path, "r")
        for lines in loadfile.readlines():  # check files content and take options
            if len(lines.split(":")) > 1:
                arg = lines.split(":")[1].replace("\n", "")
            else:
                arg = ""
            if "directory:" in lines:
                directory = arg
            elif "emailV:" in lines:
                if "False" in arg:
                    arg = False
                else:
                    arg = True
                emailV = arg
            elif "usern:" in lines:
                usern = arg
            elif "passwd:" in lines:
                pasw = arg
            elif "dest:" in lines:
                dest = arg
            elif "maldo:" in lines:
                maldo = arg
            elif "mal_move_dest:" in lines:
                mal_move_dest = arg
            elif "sqlxss:" in lines:
                if "False" in arg:
                    sqlxss = False
                else:
                    sqlxss = True
            elif "attack_do:" in lines:
                attack_do = arg
            elif "posts:" in lines:
                if "False" in arg:
                    posts = False
                else:
                    posts = True
        loadfile.close()
        return True
    else:
        return False


def send_mail(user, paswd, destination, subject, msg):  # send mail function . using gmail
    if type(destination) is not list:
        destination = [destination]
        destination = ', '.join(destination)
    else:
        destination = ', '.join(destination)
    message = "From: {0}\n To: {1} \n Subject: {2} \n\n {3}".format(user, destination, subject, msg)
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(user, paswd)
        server.sendmail(user, destination, message)
        server.close()
        return True
    except:
        return False


def startapp(folder, emil, mldo, sql_xss, attc, post):  # start scanning in background with arguments . uses 'nohup' command
    global filename
    command = ["sudo","nohup","python3.5",str(filename),str(folder),str(emil),str(mldo),str(sql_xss), str(attc), str(post), "&"]
    if subprocess.Popen(command):
        return True
    else:
        return False


def stopapp():  # search processes and find palware processes . then kill them
    global filename
    ipx = bashoutput("ps -C \"python3.5 mal_detect.py\" ").split("\n")
    inops = bashoutput("ps -C inotifywait").split("\n")
    if len(ipx) > 1:
        num1 = 0
        for pi in ipx:
            if num1 > 0:
                pid = pi.split()[0]
                subprocess.Popen(["sudo", "kill", str(pid)])
            else:
                num1 += 1

    if len(inops) > 1:
        num2 = 0
        for ino in inops:
            if num2 > 0:
                inopid = ino.split()[0]
                subprocess.Popen(["sudo", "kill", str(inopid)])
            else:
                num2 += 1
    if num1 < 2 and num2 < 2:
        return False
    return True


def bashexec(command):  # executing bash commands and Do Not return that outputs
    process = subprocess.getstatusoutput(command)
    if process[0] == 0:
        return True
    else:
        return False


def bashoutput(bashc):  # executing bash commands and return that outputs
    basherr = r"(\/bin\/sh: [0-9]*: [a-zA-Z0-9 !@#$%^&*()\[\]{}\-=+<>\/?.,:;'\"\\|_]*: not found)"
    bash = subprocess.getoutput(bashc)
    if re.search(basherr, bash, re.IGNORECASE):  # checking error existence
        return False
    else:
        return bash


def get_opt():  # get options from user keyboard and use above functions for handling inputs.
    global directory, internal, unsafef, uploadfunc, uploadform, filemanage, extensions, colors, emailV, usern, pasw, dest, maldo, mal_move_dest, sqlxss, attack_do, posts
    global iplistpath, apache2confpath
    config_path = "inc/config.conf"  # config path for saving/loading options
    while True:
        optnum = input(" {0}Available Options : \n 1- Select scanning settings "  # get options from keyboard
              "\n 2- (Save/Load) Configurations"
              "\n 3- Ban Ip(s) manually"
              "\n 4- Start scanning in background"
              "\n 5- Stop scanning "
              "\n 6- Credits "
              "\n 7- Exit "
              "\n {1}-->{2}".format(colors["w"], colors["r"], colors["n"]))
        if optnum.isdigit():
            optnum = int(optnum)
        else:
            print(" {0} No Option found ! Please Enter an number \n {1}".format(colors["r"], colors["n"]))
        if optnum == 1:  # check submitted option
            setnum = input("{0} 1- File(s) Watching(Default = Enable) \n 2- SQLI/XSS scanning (Default = Disable)\n 3- Sending email for alerting (Default = Disable)\n 4- Select Reaction after threat(s) founding (Default = Just Alerting)\n 5- Monitoring POST method request(s)  \n {1}-->{2}".format(colors["w"], colors["r"], colors["n"]))
            setnum = int(setnum)
            if setnum == 1:
                scnum = input("{0} Enable file(s) watching (recommended) ? (y/n) \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                if scnum == "y":
                    directory = input("{0}Enter directory name (for current directory enter ' . ') \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                    if directory[-1] != "/":
                        directory = directory + "/"
                    print("{0} File watcher enabled ! {1}\n ".format(colors["g"], colors["n"]))
                    if not os.path.exists(directory):
                        print("{0} No Such Directory ! {1}".format(colors["r"], colors["n"]))
                        directory = ""
                else:
                    directory = False
                    print("{0} File watcher disabled ! {1}\n ".format(colors["g"], colors["n"]))

            elif setnum == 2:
                sqlcheck = input("{0} Scanning for SQLI/XSS Attacks ? (y/n) \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                if sqlcheck == "y":
                    sqlxss = True
                    print("{0} SQLI/XSS attack scanning activated ! {1} \n".format(colors["g"], colors["n"]))
                else:
                    print("{0} SQLI/XSS attack scanning disabled ! {1} \n".format(colors["g"], colors["n"]))
            elif setnum == 3:
                sndmail = input("{0} Sending email for alerts ? (y/n)")
                if sndmail == "y":
                    usern = input(" {0}Enter sender gmail username : \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                    pasw = input(" {0}Enter sender gmail password : \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                    dest = str(input(" {0}Enter receiver gmail name(s) : (separate each address with ' , ') \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"])))
                    subject = "Test Email"
                    msg = "This is a test mail for testing email sendig !"
                    print(" {0} Sending ... \n {1}".format(colors["o"], colors["n"]))
                    if send_mail(usern, pasw, dest, subject, msg):
                        print(" {0} Email Sent Successfully ! {1}".format(colors["o"], colors["n"]))
                        open("inc/mail.txt", "w").write("{0}:{1}\n{2}".format(usern, pasw, dest))
                        emailV = True
                        print("{0} Email sending activated !\n {1}".format(colors["g"], colors["n"]))
                    else:
                        print(" {0} Error ! Please re enter Your informations or check your gmail settings ! {1}".format(colors["r"], colors["n"]))
            elif setnum == 4:
                type = input("{0} 1- Set this option for malware detection\n 2- set this option for SQLI/XSS attacks .\n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                if int(type) == 1:
                    domal = input("{0} 1- Move Malwares to another directory and save log/sendMail .\n 2- Do nothing against malwares and just save log/sendMail .\n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                    if str(domal).isdigit():
                        domal = int(domal)
                        if domal == 1:
                            mal_move_dest = str(input("{0} Please enter your directory (from this script directory) \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"])))
                            maldo = "move"
                        elif domal == 2:
                            maldo = "log"
                        else:
                            pass
                    else:
                        print("{0} Please Enter A Valid Option !{1}".format(colors["r"], colors["n"]))
                elif int(type) == 2:
                    attdo = input("{0} 1- Just alert attacks\n 2- Block attacker ip(s) \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                    if int(attdo) == 1:
                        print("{0} Done !\n {1}".format(colors["g"], colors["n"]))
                    elif int(attdo) == 2:
                        rootdir = input("{0} Please Enter your website root directory \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                        if os.path.exists(rootdir):
                            apache2confline = open("inc/apache2.conf", "r").readline()
                            apache2conf = open("inc/apache2.conf", "r").read()
                            apache2confread = open(apache2confpath, "r").read().replace(apache2conf, "")
                            apache2confrep = open("inc/apache2.conf", "r").read().replace(apache2confline, "<Directory {0}>\n".format(rootdir))
                            if apache2confrep in apache2confread :
                                attack_do = rootdir
                                print("{0} Automatic ip blocker is already activated !\n {1}".format(colors["g"],colors["n"]))
                            else:
                                open(apache2confpath, "w").write(apache2confread + "\n\n" + apache2confrep)
                                open("inc/apache2.conf", "w").write(apache2confrep)
                                attack_do = rootdir
                                bashexec("sudo service {0} reload".format(apachename))
                                print("{0} Automatic ip blocker has been activated !\n {1}".format(colors["g"], colors["n"]))
                else:
                    print("{0} Please Enter A Valid Option !{1}".format(colors["r"], colors["n"]))
            elif setnum == 5:
                post_a = input("{0} Active POST method request Monitoring ? (y/n) [NOTICE : This option may DECREASE your server performance]\n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                if post_a == "y":
                    apache2confr = open(apache2confpath, "r").read()
                    if "LogLevel dumpio:trace7\nDumpIOInput On" in apache2confr:
                        posts = True
                        print("{0} POST method requests monitoring is already activated !\n {1}".format(colors["g"], colors["n"]))
                    else:
                        open(apache2confpath, "w").write(apache2confr + "\nLogLevel dumpio:trace7\nDumpIOInput On")
                        posts = True
                        bashexec("sudo service {0} reload".format(apachename))
                        print("{0} POST method requests monitoring activated !\n {1}".format(colors["g"], colors["n"]))
                else:
                    open(apache2confpath, "w").write(apache2confr.replace("LogLevel dumpio:trace7\nDumpIOInput On", ""))
                    print("{0} POST method requests monitoring disabled !\n {1}".format(colors["g"], colors["n"]))
            else:
                pass
        elif optnum == 2:
            saveload = str(input(" {0}1- Save current options \n 2- Load saved options \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"])))
            if saveload.isdigit():
                saveload = int(saveload)
                if saveload == 1:
                    if saveopt(config_path):
                        print("{0} Configuration successfully saved ! {1}".format(colors["o"], colors["n"]))
                    else:
                        print("{0} Error While saving configurations ! {1}".format(colors["r"], colors["n"]))
                elif saveload == 2:
                    if loadopt(config_path) == "OK":
                        print("{0} Script configuration loaded successfully ! {1}".format(colors["o"], colors["n"]))
                    else:
                        print("{0} No configuration file found ! please save configs first ! {1}".format(colors["r"], colors["n"]))
                else:
                    print("{0} No option found ! please enter again ! {1}".format(colors["r"], colors["n"]))
            else:
                print(" {0} No Option found ! Please Enter an number \n {1}".format(colors["r"], colors["n"]))

        elif optnum == 3:
            ips = input("{0} Enter ip(s) (use comma's for seprating ip's) . You can find suspicious ip's in : /var/log/palware/maldetect.log \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
            ips = str(ips).split(",")
            if directory == "":
                rootdir = input("{0} Please Enter your website root directory \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
                if rootdir[-1] != "/":
                    rootdir = rootdir + "/"
                if os.path.exists(rootdir):
                    apache2confline = open("inc/apache2.conf", "r").readline()
                    apache2conf = open("inc/apache2.conf", "r").read()
                    apache2confread = open(apache2confpath, "r").read().replace(apache2conf, "")
                    apache2confrep = open("inc/apache2.conf", "r").read().replace(apache2confline, "<Directory {0}>\n".format(rootdir))
                    open(apache2confpath, "w").write(apache2confread + "\n\n" + apache2confrep)
                    open("inc/apache2.conf", "w").write(apache2confrep)
                    ipss = "1"
                    for ip in ips:
                        if ipss == "1":
                            ipss = "Require not ip " + ip
                        else:
                            ipss = ipss + "\n" + "Require not ip " + ip
                    ipsread = open(iplistpath, "r").read()
                    open(iplistpath, "w").write(ipsread + "\n{0}".format(ipss))
                    bashexec("sudo service {0} reload".format(apachename))
                else:
                    print(" {0} Directory does not exists ! {1} ".format(colors["r"], colors["n"]))
        elif optnum == 4:  # collecting and fixing necessary information for start scanning and passing arguments
            if directory == "":
                print(" {0} Please Define an directory for scan ! {1} ".format(colors["r"], colors["n"]))
            else:
                if directory == False:
                    directory = ""
                else:
                    directory = "-d{0}".format(directory)
                if emailV:
                    email = "-Etrue"
                else:
                    email = ""
                if maldo == "move":
                    maldo = "-m{0} -M{1}".format(maldo, mal_move_dest)
                else:
                    maldo = "-m{0}".format(maldo)
                if sqlxss:
                    sqlxss = "-s"
                else:
                    sqlxss = ""
                if attack_do != "":
                    attack_do = "-a{0}".format(attack_do)
                if posts:
                    posts = "-ptrue"
                else:
                    posts = ""
                open("/var/log/audit/audit.log", "w").write("")
                open("/var/log/palware/apache2.log", "w").write("")
                open("/var/log/palware/filechangelog.txt", "w").write("")
                open("/var/log/palware/post.log", "w").write("")
                if startapp(directory, email, maldo, sqlxss, attack_do, posts):
                    print(" {0}\n ===\n Malware scanning started successfully !  \n ===\n{1}".format(colors["o"], colors["n"]))
                    time.sleep(2)
                else:
                    print("{0} Error While starting scan :({1}".format(colors["r"], colors["n"]))
        elif optnum == 5:
            if stopapp():
                print(" {0}===\n Script Stopped successfully !\n ===\n{1}".format(colors["o"], colors["n"]))
                time.sleep(2)
            else:
                print(" {0}No script is running !{1}".format(colors["r"], colors["n"]))
        elif optnum == 6:
            print("{0} Coded {1} By Mad Ant - SeedPuller@gmail.com {2} \n Special Thanks To My Dear Friend {3}Bl4ck MohajeM {4}\n Thanks To All Guys  Who Helped Me And Who Did Not.{5}".format(colors["o"], colors["r"], colors["o"], colors["r"], colors["o"], colors["n"]))
            time.sleep(2)
        elif optnum == 7:
            break
        else:
            print("No options found")
get_opt()
