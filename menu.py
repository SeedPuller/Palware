import subprocess
import re
import time
import smtplib
import os
import sys
# setting necessary vars
if not os.path.exists("inc/installed.txt"):
    sys.exit(1)
colors = {"g": "\033[32m", "n": "\033[m", "r": "\033[31m", "w": "\033[37m", "o": "\033[33m"}
print(colors["r"] + open("inc/banner.txt").read() + colors["n"])
print(" %s [+]  Web Malware Scanner Ver 2.1\n\n%s" % (colors["g"], colors["n"]))
# vars
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
# defining functions


def saveopt(conf_path):  # saving options in 'conf_path'
    global sqlxss, directory, internal, unsafef, uploadfunc, uploadform, filemanage, extensions, emailV, usern, pasw, dest, maldo, mal_move_dest
    if os.path.isfile(conf_path):
        os.remove(conf_path)  # if option has been exsits , remove it to save new options
    savefile = open(conf_path, "w")
    if savefile.write("directory:{0}\nemailV:{1}\nusern:{2}\npasswd:{3}\ndest:{4}\nmaldo:{5}\nmal_move_dest:{6}\nsqlxss:{7}".format(directory, emailV, usern, pasw, dest, maldo, mal_move_dest, sqlxss)):
        return True
    else:
        return False


def loadopt(conf_path):  # load options from 'conf_path'
    global sqlxss, directory, internal, unsafef, uploadfunc, uploadform, filemanage, extensions, emailV, usern, pasw, dest, maldo, mal_move_dest
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
        loadfile.close()
        return "OK"

    else:
        return "NOFLIE"


def send_mail(user, paswd, destination, subject, msg):  # send mail function using gmail
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


def startapp(folder, emil, mldo, sql_xss):  # start scanning in background with arguments . uses 'nohup' command
    global filename
    command = ["sudo","nohup","python3",str(filename),str(folder),str(emil),str(mldo),str(sql_xss), "&"]
    if subprocess.Popen(command):
        return True
    else:
        return False


def stopapp():  # search proccesses and find scannings procces then kill them
    global filename
    regex = r"(root[\s]*[0-9]*[\s\S0-9]* -d)"
    psx = bashoutput("ps -A -f | grep \"sudo nohup python3 {0}\" " .format(filename))
    search = re.search(regex, psx, re.IGNORECASE)
    if search is not None:
        pid = int(search.group().split()[1])
        kill = bashoutput("sudo kill {0}".format(pid))
        if "No such process" not in kill:
            return True
        else:
            return False
    else:
        return False


def bashexec(command):  # executing bash commands and Do Not return that outputs
    process = subprocess.getstatusoutput(command)
    if process[0] == 0:
        return True
    else:
        return False


def bashoutput(bashc):  # executing bash commands and return that outputs
    basherr = r"(\/bin\/sh: [0-9]*: [a-zA-Z0-9 !@#$%^&*()\[\]{}\-=+<>\/?.,:;'\"\\|_]*: not found)"
    bash = subprocess.getoutput(bashc)
    if re.search(basherr, bash, re.IGNORECASE):  # check error existence
        return False
    else:
        return bash


def get_opt():  # get options from user keyboard and use above functions for handling those.
    global directory, internal, unsafef, uploadfunc, uploadform, filemanage, extensions, colors, emailV, usern, pasw, dest, maldo, mal_move_dest, sqlxss
    config_path = "inc/config.conf"  # config path for saving/loading options
    while True:

        optnum = input(" {0}Available Options : \n 1- Add scanning directory (required) "  # get options from keyboard
              "\n 2- Add Your gmail for sending and receiving emails"
              "\n 3- What should i do with malwares ? (Default = Just Logging)"
              "\n 4- SQL/XSS scanning (Default = Disable)"
              "\n 5- (Save/Load) Configurations"
              "\n 6- Start scanning in background"
              "\n 7- Stop scanning "
              "\n 8- Credits "
              "\n 9- Exit "
              "\n {1}-->{2}".format(colors["w"], colors["r"], colors["n"]))
        if optnum.isdigit():
            optnum = int(optnum)
        else:
            print(" {0} No Option found ! Please Enter an number \n {1}".format(colors["r"], colors["n"]))
        if optnum == 1:  # check submitted option
            directory = input("{0}Enter directory name (for current directory enter ' . ') \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
            if not os.path.exists(directory):
                print("{0} No Such Directory ! {1}".format(colors["r"], colors["n"]))
                directory = ""
        elif optnum == 2:  # get email necessary informations
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
            else:
                print(" {0} Error ! Please re enter Your informations or check your gmail settings ! {1}".format(colors["r"], colors["n"]))
        elif optnum == 3:
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
        elif optnum == 4:
            sqlcheck = input("{0} Scanning for SQLI/XSS ? (y/n) \n {1}-->{2} ".format(colors["w"], colors["r"], colors["n"]))
            if sqlcheck == "y":
                sqlxss = True
        elif optnum == 5:
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

        elif optnum == 6:  # collecting and fixing necessary information for start scanning and passing arguments
            if directory == "":
                print(" {0} Please Define an directory for scan ! {1} ".format(colors["r"], colors["n"]))
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
                if startapp(directory, email, maldo, sqlxss):
                    print(" {0}\n ===\n Malware scanning started successfully !  \n ===\n{1}".format(colors["o"], colors["n"]))
                    time.sleep(2)
                else:
                    print("{0} Error While starting scan :({1}".format(colors["r"], colors["n"]))
        elif optnum == 7:
            if stopapp():
                while stopapp():  # run that function until return false (there is no scanning proccess anymore)
                    pass
                print(" {0}===\n Script Stopped successfully !\n ===\n{1}".format(colors["o"], colors["n"]))
                time.sleep(2)
            else:
                print(" {0}Error While stopping scan :({1}".format(colors["r"], colors["n"]))
        elif optnum == 8:
            print("{0} Coded {1} By Mad Ant - SeedPuller@gmail.com {2} \n Special Thanks to my dear friend {3}Bl4ck MohajeM {4}\n Thanks to all my friends who helped me and who didnt.{5}".format(colors["o"], colors["r"], colors["o"], colors["r"], colors["o"], colors["n"]))
            time.sleep(2)
        elif optnum == 9:
            break
        else:
            print("No options found")
get_opt()
