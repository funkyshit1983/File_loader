#!/usr/bin/env python

import os
import requests
import time
import re
import argparse


tech_support = "198.58.127.81"
user = os.environ['USER']
home = os.environ['HOME']

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def key_file_genrator():
    file_location = os.path.exists(home + "/.key_path.txt")
    if file_location:
        key_path = open(home + "/.key_path.txt",'r')
        key_capture = key_path.read()
        return key_capture 
    else:
        user_input = raw_input(bcolors.HEADER + "\nEnter the path of your key: " + bcolors.ENDC)
        with open(home + "/.key_path.txt",'w+') as file:
           file.write(user_input)
           key_path = open(home + "/.key_path.txt",'r')
           key_capture = key_path.read()
           return key_capture 


def get_infinikey(): # asks drom the user the infinikey path + name 
    while True:
        user_input = raw_input(bcolors.HEADER + "\nEnter the Infinikey location - [Example - /tmp/key-2786-ibox1339]: " + bcolors.ENDC)
        question = raw_input(bcolors.WARNING + "\nThe Infinikey location is '{}' ,Are you sure this is correct [Y/N]? ".format(user_input) + bcolors.ENDC)
        if question == 'Y':
            return user_input
            break
        elif question == 'N': 
            print bcolors.FAIL + "\nPlease type again the path of the infinikey" + bcolors.ENDC
        else: 
            print bcolors.WARNING + "\nPlease choose 'Y' or 'N' " + bcolors.ENDC


def print_key():
    print bcolors.OKBLUE + '\nkey path ' + key_file_genrator() + bcolors.ENDC


def key_test(key_path):
    ssh_test = os.system("ssh -i {} {}@{} 'date > /dev/null' ".format(key_path,user,tech_support))
    if ssh_test != 0:
        print bcolors.FAIL + "\nThe key {} is in correct, can't connect to the tech-support server".format(key_path)
        print "\nPlease run the script again and check your loaction your ssh key again"
        exit() 
        


def version_microcode():
    # \d\.\d\.\d{1,2}\.\d{1,3}
    code_pattern = re.compile(
        "\d[.]\d[.]\d{1,2}[.]\d{1,3}")  # this will match the following pattern x.x.x.x or x.x.xx.x or x.x.xx.xx
    while True:
        user_input = raw_input(bcolors.HEADER + "\nPlease choose the Microcode version - [Example - 4.0.1.10]: " + bcolors.ENDC)
        if re.search(code_pattern, user_input) == None:
            print bcolors.FAIL + "\nPlease enter the right Syntax - x.x.x.x" + bcolors.ENDC
        else:
            break
    microcode_repo_url = "http://dist.infinidat.com/infinibox/GA/"
    infinibox_code_name = "infinibox-{}.tar".format(user_input)
    return infinibox_code_name


def wget_microcode(microcode_version): # Dowloads the microcode from dist 
    microcode_repo_url = "http://dist.infinidat.com/infinibox/GA/"
    time.sleep(1)
    print bcolors.OKGREEN + "\nPlease hold, downloading {}\n".format(microcode_version)
    download_code = os.system("wget --no-verbose -q {}{}".format(microcode_repo_url, microcode_version))
    if download_code == 0:
        print bcolors.OKGREEN + "{} was downloaded to your local directory\n ".format(microcode_version) + bcolors.ENDC
    else:
        print bcolors.FAIL + "The Microcode version you requested can't be found" + bcolors.ENDC
        while True:
            question = raw_input(bcolors.HEADER + "\nDo you wish to try again[Y/N]? " + bcolors.ENDC)
            if question == 'Y':
                wget_microcode(version_microcode()) 
            else:
                print bcolors.FAIL + "\nPlease check the code version again and download it spereatly" + bcolors.ENDC
                break
    

def version_sa_utils(): #returns the latest sa-utils version 
    sa_version_json = requests.get("http://dist.infinidat.com/ibox_sa/latest/sa-utils/release.json").json()['version']
    sa_version_name = "sa-utils-{}.noarch.rpm".format(sa_version_json)
    return sa_version_name


def wget_sa_utils(): #downloads the latest sa-utils from dist to the current directory 
    sa_version_name = version_sa_utils()
    sa_full_path = "http://dist.infinidat.com/ibox_sa/latest/sa-utils/{}".format(sa_version_name)
    print bcolors.OKGREEN + "\nPlease hold, downloading {}\n".format(sa_version_name) + bcolors.ENDC
    wget_sa = os.system("wget --no-verbose -q {}".format(sa_full_path))
    if wget_sa == 0:
        print bcolors.OKGREEN + "{} was downloaded to your local directory \n".format(sa_version_name) + bcolors.ENDC
    else:
        pass
    

def version_remote_support(): #returns the lastest version of the remote-support package 
    remote_support_json_url = "http://repo.lab.il.infinidat.com/packages/main-stable/index/packages/remote-support/releases.json"
    remote_support_json_get = requests.get(remote_support_json_url).json()[0]
    remote_support_version = "remote-support-" + remote_support_json_get['version'] + "-linux-centos-6-x64.rpm"
    return remote_support_version


def wget_remote_support(): #Downloads the lastest remote-support package to the current directory
    remote_support_version = version_remote_support()
    json_url = "http://repo.lab.il.infinidat.com/packages/main-stable/index/packages/remote-support/releases.json"
    dist_url = "http://repo.lab.il.infinidat.com"
    json_release = requests.get(json_url).json()[0]
    for dist in json_release['distributions']:
        if dist['platform'] == "linux-centos-6":
            filepath = dist['filepath']
    print bcolors.OKGREEN + "\nplease hold, downloading {}\n ".format(remote_support_version)
    wget_remote_support = os.system("wget --no-verbose -q {}{}".format(dist_url, filepath))
    if wget_remote_support == 0:
        print bcolors.OKGREEN +  "{} was downloaded to your local directory\n".format(remote_support_version) + bcolors.ENDC
    else:
        pass
    

def version_snaprotator(): #returns the latest version of the snaprotator
    snaprotator_json_url = "http://repo.lab.il.infinidat.com/packages/main-stable/index/packages/snaprotator/releases.json"
    snaprotator_json_get = requests.get(snaprotator_json_url).json()[0]
    snaprotator_version = "snaprotator-" + snaprotator_json_get['version'] + "-linux-centos-7-x64.rpm"
    return snaprotator_version


def wget_snaprotator(): #Downloads the lastest version of the snaprotator to the current directory
    snaprotator_version = version_snaprotator()
    snaprotator_json_url = "http://repo.lab.il.infinidat.com/packages/main-stable/index/packages/snaprotator/releases.json"
    snaprotator_json_get = requests.get(snaprotator_json_url).json()[0]
    dist_url = "http://repo.lab.il.infinidat.com"
    for data in snaprotator_json_get['distributions']:
        if data['platform'] == "linux-centos-7":
            filepath = data['filepath']
    print bcolors.OKGREEN +  "\nplease hold, downloading {}\n".format(snaprotator_version)
    wget_snaprotator = os.system("wget --no-verbose -q {}{}".format(dist_url, filepath))
    if wget_snaprotator == 0:
        print "{} was downloaded to your local directory\n".format(snaprotator_version) + bcolors.OKGREEN
    else:
        pass
    

def versions_list(infinikey,infinibox_code_version): #outputs all the versions before uploading them to the tech-support 
    sa_utils_version = version_sa_utils()
    snaprotator_version = version_snaprotator()
    remote_support_version = version_remote_support()
    line_s = 82 * "-"
    versions = "1) {}\n2) {}\n3) {}\n4) {}\n5) {}\n".format(infinikey,infinibox_code_version,version_sa_utils(),version_snaprotator(),
                                                   version_remote_support())
    print bcolors.OKGREEN + "\nThe following packages will be uploaded to tech-support:/support/cs-repo directory\n" + line_s + "\n" + versions
    hold = raw_input("Press Enter to continue: \n") + bcolors.ENDC
    

def scp_sa_utils_tech_support(key_path):
    print bcolors.OKGREEN + "{} is being transffered to the tech-support\n".format(version_sa_utils()) 
    scp_sa_utils = os.system("scp -i {} {} {}@{}:/support/cs-repo/".format(key_path,version_sa_utils(),user,tech_support))  
    if scp_sa_utils == 0:
        print bcolors.OKBLUE + "\nThe {} was transferred sucessfully to tech-support:/support/cs-repo\n".format(version_sa_utils()) + bcolors.ENDC


def scp_snaprotator_tech_support(key_path):
    print bcolors.OKGREEN + "{} is being transffered to the tech-support\n".format(version_snaprotator())
    scp_snaprotator = os.system("scp -i {} {} {}@{}:/support/cs-repo".format(key_path,version_snaprotator(),user,tech_support))
    if scp_snaprotator == 0:
        print bcolors.OKBLUE + "\nThe {} was transferred sucessfully to tech-support:/support/cs-repo\n".format(version_snaprotator()) + bcolors.ENDC


def scp_remote_support_tech_support(key_path):
    print bcolors.OKGREEN + "{} is being transffered to the tech-support\n".format(version_remote_support())
    scp_remote_support = os.system("scp -i {} {} {}@{}:/support/cs-repo".format(key_path,version_remote_support(),user,tech_support))
    if scp_remote_support == 0:
        print bcolors.OKBLUE + "\nThe {} was transferred sucessfully to tech-support:/support/cs-repo\n".format(version_remote_support()) + bcolors.ENDC


def scp_microcode_tech_support(key_path,microcode_version):
    print bcolors.OKGREEN + "{} is being transffered to the tech-support\n".format(microcode_version)
    scp_microcode = os.system("scp -i {} {} {}@{}:/support/cs-repo".format(key_path,microcode_version,user,tech_support))
    if scp_microcode == 0:
        print bcolors.OKBLUE + "\nThe {} was transferred sucessfully to tech-support:/support/cs-repo\n".format(microcode_version) + bcolors.ENDC


def scp_infinikey_tech_support(key_path,infinikey):
    print bcolors.OKGREEN + "\n{} is being transffered to the tech-support\n".format(infinikey)
    scp_infinikey = os.system("scp -i {} {} {}@{}:/support/cs-repo".format(key_path,infinikey,user,tech_support))
    if scp_infinikey == 0:
        print bcolors.OKBLUE + "\nThe {} was transferred sucessfully to tech-support:/support/cs-repo\n".format(infinikey) + bcolors.ENDC
       
def all():
    key_path = key_file_genrator()
    key_test(key_path)
    print_key()
    infinibox_code_version = version_microcode()
    infinikey = get_infinikey()
    wget_microcode(infinibox_code_version)
    wget_sa_utils()
    wget_remote_support()
    wget_snaprotator()
    versions_list(infinikey,infinibox_code_version)
    scp_microcode_tech_support(key_path,infinibox_code_version)
    scp_sa_utils_tech_support(key_path)
    scp_snaprotator_tech_support(key_path)
    scp_remote_support_tech_support(key_path)
    scp_infinikey_tech_support(key_path,infinikey)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-ik", "--infinikey", help="uploads the infinikey to the tech-support", action="store_true", )
    parser.add_argument("-s", "--sa-utils", help="uploads the latest sa-utils to tech-support", action="store_true", )
    parser.add_argument("-sr", "--snaprotator", help="uploads the latest snaprotator to tech-support",
                        action="store_true")
    parser.add_argument("-m", "--microcode", help="uploads the microcode to tech-support", action="store_true")
    parser.add_argument("-r", "--remote_support", help="uploads the latest remote-support to tech-support",
                        action="store_true")
    parser.add_argument("-a", "--all", help="uploads all the files to tech-support", action="store_true")
    args = parser.parse_args()
    if args.infinikey:
        key_path = key_file_genrator()
        infinikey = get_infinikey()
        print_key()
        key_test(key_path)
        scp_infinikey_tech_support(key_path,infinikey)
    if args.sa_utils:
        key_path = key_file_genrator()
        key_test(key_path)
        print_key()
        wget_sa_utils()
        scp_sa_utils_tech_support(key_path)
    if args.snaprotator:
        key_path = key_file_genrator()
        key_test(key_path)
        wget_snaprotator()
        scp_snaprotator_tech_support(key_path)
    if args.remote_support:
        key_path = key_file_genrator()
        key_test(key_path)
        wget_remote_support()
        scp_remote_support_tech_support(key_path)
    if args.microcode:
        key_path = key_file_genrator()
        key_test(key_path)
        infinibox_code_version = version_microcode()
        wget_microcode(infinibox_code_version)
        scp_microcode_tech_support(key_path,infinibox_code_version)
    if args.all:
        all()
        
        


if __name__ == '__main__':
    main()
