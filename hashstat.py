#!/usr/bin/python3

import re
import csv
import pprint
import subprocess
from collections import OrderedDict
from subprocess import check_output
from tabulate import tabulate
from operator import itemgetter
from collections import Counter

############################################
# by Leon Johnson
#
# This is a program to parse pwdump files
# and extract stats on the NT and LM password
# hashes. Also if john was used to crack
# passwords, this program will give stats
# on cracked passwords using john the ripper
#
# Debuging:
#       python -m pdb program.py
#
# this program will do the following:
# [x] remove machine accounts
# [x] injest ntds pwdump file
# [x] identify # of LM hashes
# [x] identify # of NT hashes
# [x] identify # of reused NT hashes
# [x] identify # of reused LM hashes
# [x] fix the removal of machine accounts $
# [x] show cracked passwords using john
# [ ] identify # of domain admin accounts that reuse password
# [ ] identify # domain admins with LM hashes
# [ ] add pivot table to list all users that share password
# [ ] add html output option
# [ ] add formating aligning text and numbers with .format() t.ly/upn8

# ----------------------------------
# Colors
# ----------------------------------
NOCOLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHTGRAY='\033[0;37m'
DARKGRAY='\033[1;30m'
LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHTBLUE='\033[1;34m'
LIGHTPURPLE='\033[1;35m'
LIGHTCYAN='\033[1;36m'
WHITE='\033[1;37m'


import sys # Used by len, exit, etc
import argparse # Parser for command-line options, arguments and sub-commands

banner = """
 .S    S.    .S_SSSs      sSSs   .S    S.     sSSs  sdSS_SSSSSSbs   .S_SSSs    sdSS_SSSSSSbs
.SS    SS.  .SS~SSSSS    d%%SP  .SS    SS.   d%%SP  YSSS~S%SSSSSP  .SS~SSSSS   YSSS~S%SSSSSP
S%S    S%S  S%S   SSSS  d%S'    S%S    S%S  d%S'         S%S       S%S   SSSS       S%S
S%S    S%S  S%S    S%S  S%|     S%S    S%S  S%|          S%S       S%S    S%S       S%S
S%S SSSS%S  S%S SSSS%S  S&S     S%S SSSS%S  S&S          S&S       S%S SSSS%S       S&S
S&S  SSS&S  S&S  SSS%S  Y&Ss    S&S  SSS&S  Y&Ss         S&S       S&S  SSS%S       S&S
S&S    S&S  S&S    S&S  `S&&S   S&S    S&S  `S&&S        S&S       S&S    S&S       S&S
S&S    S&S  S&S    S&S    `S*S  S&S    S&S    `S*S       S&S       S&S    S&S       S&S
S*S    S*S  S*S    S&S     l*S  S*S    S*S     l*S       S*S       S*S    S&S       S*S
S*S    S*S  S*S    S*S    .S*P  S*S    S*S    .S*P       S*S       S*S    S*S       S*S
S*S    S*S  S*S    S*S  sSS*S   S*S    S*S  sSS*S        S*S       S*S    S*S       S*S
SSS    S*S  SSS    S*S  YSS'    SSS    S*S  YSS'         S*S       SSS    S*S       S*S
       SP          SP                  SP                SP               SP        SP
       Y           Y                   Y                 Y                Y         Y

"""

parser = argparse.ArgumentParser(description='Program discreption.')
parser.add_argument('ntds', action='store', metavar='ntds file', help="Submit ntds.dit file in pwdump format: domain\\user:rid:lmhash:nthash:::")
parser.add_argument("-t", "--top", action="store_true", help="show top ten hashes used")
parser.add_argument("-d", "--details", action="store_true", help="show all details found")
parser.add_argument("-c", "--cracked", action='store_true', help='show top ten')
parser.add_argument("-lm", action='store_true', help='show top ten')
parser.add_argument("-nt", action='store_true', help='show top ten')
parser.add_argument("-e", action='store_true', help='show identical user/pass')
parser.add_argument('-m', '--matching', action='store_true', help='Find accounts where username equals password')


#group = parser.add_mutually_exclusive_group()
group = parser.add_argument_group('Additional options')

group.add_argument('-additional-flag', action='store_true', help='Additional flag discription')

def main():

    if len(sys.argv)==1:
            print( banner )
            parser.print_help()
            sys.exit(1)

    options = parser.parse_args()

    class ntds:
        usernames = []
        passwords = []
        rids = []
        nt_hashes = []
        lm_hashes = []
        lm_total = []
        lm_count = []
        nt_total = []
        ntds = []
        details = False
        top_hash = False
        top_cracked = False
        filename = ""
        file_data = ""
        machine_accounts = 0
        nt_stats = []
        lm_stats = []
        nt_max = 0
        lm_max = 0 

    my_ntds = ntds()
    my_ntds.details = options.details
    my_ntds.top_hash = options.top
    my_ntds.top_cracked = options.cracked
    my_ntds.filename = options.ntds
    my_ntds.lm = options.lm
    my_ntds.nt = options.nt
    matching = options.matching


    # try to open file with hashes
    try:
        x = open(options.ntds, newline='')
    except IOError:
        print(RED+"File not accessible"+NOCOLOR)
        exit(-1)

    # read file into file_data variable
    my_ntds.file_data = x.readlines()
    x.close()

    # parse data add to struct
    parse_ntds(my_ntds)

    print(CYAN+"\nThe are the statistics based on the pwdump file"+NOCOLOR)
    print(CYAN+"These statistics exclude machine accounts."+NOCOLOR)
    print(CYAN,my_ntds.machine_accounts, "machine accounts were removed from these stats."+NOCOLOR)
    print_ntds_stats(my_ntds, matching)

def parse_ntds(ntds):
    for line in ntds.file_data:
        if re.search(":::", line):
            # we remove machine accounts on this line
            if not re.search("\$",line):
                x = line.split(":")
                ntds.usernames.append(x[0])
                ntds.rids.append(x[1])
                if x[2].lower() != 'aad3b435b51404eeaad3b435b51404ee':
                    ntds.lm_hashes.append(x[2])
                ntds.nt_hashes.append(x[3])
                # t.ly/YmZgE
                #ntds.ntds.append({"user":x[0], "rid":x[1], "lm":x[2], "nt":x[3]})
            else:
                ntds.machine_accounts += 1
    # pipal style get dup values of list
    ntds.nt_stats, ntds.nt_total, ntds.nt_max = get_top_ten_reused_hashes(ntds.nt_hashes)
    ntds.lm_stats, ntds.lm_total, ntds.lm_max = get_top_ten_reused_hashes(ntds.lm_hashes)

def print_nt_stats(ntds):
    print(LIGHTGREEN+"\n[+] "+NOCOLOR, end = '')
    print("Total account NT hashes:",end='')
    print(RED,len(ntds.nt_hashes),NOCOLOR)

    print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
    print("Total unique NT hashes:",end='')
    print(RED,len(list(set(ntds.nt_hashes))),NOCOLOR)

    print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
    print("Most reused NT hash was used:",end='')
    print(RED,ntds.nt_max,NOCOLOR)

    print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
    print("Total # of duplicate NT hashes:",end='')
    print(RED,ntds.nt_total,NOCOLOR)
    print()

def print_lm_stats(ntds):
    print(LIGHTGREEN+"\n[+] "+NOCOLOR, end='')
    print("Total accounts with LM hashes:",end='')
    print(RED,len(ntds.lm_hashes),NOCOLOR)

    get_lm_count(ntds)
    print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
    print("Total LM hashes:",end='')
    print(RED,len((ntds.lm_count)),NOCOLOR)

    print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
    print("Total unique LM hash passwords:",end='')
    print(RED,(len(set(ntds.lm_count))),NOCOLOR)

    print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
    print("Most reused LM hash password was used:",end='')
    print(RED,ntds.lm_max,NOCOLOR)
    print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
    print("Total # of duplicate LM hashes:",end='')
    print(RED,ntds.lm_total,NOCOLOR)
    print()

def print_nt_top_ten(ntds):

    print(GREEN,"Top Ten duplicate NT hashes:",NOCOLOR)
    print(YELLOW+"-------------------------------------------------"+NOCOLOR)
    print_top_ten(ntds.nt_stats, len(ntds.nt_hashes))

def print_lm_top_ten(ntds):

    print(GREEN,"Top Ten duplicate LM hashes:",NOCOLOR)
    print(YELLOW+"-------------------------------------------------"+NOCOLOR)
    print_top_ten(ntds.lm_stats, len(ntds.lm_hashes))

def print_ntds_stats(ntds, matching):

    # NT Password Hashes Breakdown #==================================================
    if ntds.nt == True:
        if ntds.nt_hashes:
            print_nt_stats(ntds)

            if ntds.top_hash:
                print_nt_top_ten(ntds)

            if ntds.top_cracked:
                cracked_hash_stats(ntds.nt_hashes,"nt",ntds.filename, ntds.nt_hashes, matching)

    # LM Password Hashes Breakdown #==================================================
    if ntds.lm == True:
        if ntds.lm_hashes:
            print_lm_stats(ntds)

            if ntds.top_hash:
                print_lm_top_ten(ntds)

            if ntds.top_cracked:
                cracked_hash_stats(ntds.lm_hashes,"lm",ntds.filename,ntds.lm_count, matching)
        else:
            print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
            print("Found no LM hashes in this file\n")

def get_lm_count(ntds):
        # how to count lm hashes like john does
        # cut -d: -f3 lm.hashes | fold -w 16 | grep -v aad3b435b51404ee |wc
        for s in ntds.lm_hashes:
            s1 = s[:len(s)//2]
            s2 = s[len(s)//2:]
            ntds.lm_count += [s1]
            ntds.lm_count += [s2]
            # .discard() only removed if value exist vs .remove() which rasies error
            for value in ntds.lm_count:
                if value == 'aad3b435b51404ee':
                    ntds.lm_count.remove('aad3b435b51404ee')

def cracked_hash_stats(hashes, type_hash, filename, hash_total, matching):

    john_cracked = []
    domains = []
    passwords = []
    matches = []
    hash_format = "--format="+type_hash

    process_john = subprocess.check_output(['john', '--show', hash_format, filename])
    john_cracked = (process_john).decode("utf-8").split('\n')
    while("" in john_cracked):
        john_cracked.remove("")
    total_cracked = (john_cracked.pop().split(" ")[0])

    john_cracked = [ x for x in john_cracked if x ]     # delete empty list items

    # if lm hashes delete empty lm hashes
    if type_hash == "lm":
        john_cracked = [ x for x in john_cracked if 'aad3b435b51404eeaad3b435b51404ee' not in x.lower() ]

    # create lists of domains, passwords, and matches from list of
    # stings that look like this: "domain\user:pass:id:lm:nt:::"
    for item in john_cracked:
        # debugging
        # print(item)
        if '\\' not in item:
            domain = ""
            username, password, rid, lm, nt = item.split(':', 4)
            if "aad3b435b51404ee" == item:
                print(item)
            passwords.append(password)
            if username.lower() == password.lower():
                matches.append(username)
        else:
            domain,single_hash = item.split('\\', 1)
            username, password, rid, lm, nt = single_hash.split(':', 4)
            passwords.append(password)
            if username.lower() == password.lower():
                matches.append(username)

            domains.append( domain.lower() )

    # delete duplicate list items
    domains = set(domains)

    # My own python pipal sort and count list values
    pw_stats, pw_total, pw_max = get_top_ten_reused_hashes(passwords)

    # print cracked stats
    print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
    print("Total number of",type_hash.upper(),"hashes cracked:",end='')
    print(RED,len(john_cracked),"({:.2%})".format(len(john_cracked)/len(hashes)),NOCOLOR)
    print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
    print(type_hash.upper(),"hashes with username equal to password:",end='')
    print(RED,len(matches),NOCOLOR)
    print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
    print("Unique number of domains found in ntds file:",end='')
    print(RED,len(domains),NOCOLOR)
   
    if matching:
       print("\nAccounts where username equals password:")
       for account in matches:
         print(account)

    # print cracked top ten stats
    print()
    print(GREEN,"Top 10 Cracked",type_hash.upper(),"hashes",NOCOLOR)
    print(YELLOW+"--------------------------"+NOCOLOR)
    print_top_ten(pw_stats,len(hashes))

def print_top_ten(my_list, total):
    for x,y in my_list:
        percentage = (float(x) / total)
        if y == ""or y.lower() == "31d6cfe0d16ae931b73c59d7e0c089c0":
            y = "*BLANK HASH*"
        print(YELLOW,y,"=",x,"("+"{:.2%}".format(percentage)+")",NOCOLOR)
    print()

def get_top_ten_reused_hashes(my_list): 
    freq = {}   # unordered, no dups set of items
    stats = []

    # count the number of dups in my_list list
    for item in my_list:
        if (item in freq):
            freq[item] += 1
        else:
            freq[item] = 1

    # only count duplicate values
    hashTotalDups = 0
    blank_hash = 0
    for key in freq:
        if freq[key] != 1:
            # get count of blank hashes to subtract from total dup hashes
            if key.lower() == "31d6cfe0d16ae931b73c59d7e0c089c0":
                blank_hash = freq[key]
            elif key.lower() == "aad3b435b51404eeaad3b435b51404ee":
                blank_hash += freq[key]
            hashTotalDups += freq[key]

    # 31d6cfe0d16ae931b73c59d7e0c089c0
    freq.pop("31d6cfe0d16ae931b73c59d7e0c089c0", None)
    freq.pop("31D6CFE0D16AE931B73C59D7E0C089C0", None)

    # If freq is empty, return some default value
    if not freq:
        return [[], 0, 0]  # Just an example, adjust this as needed

    hashMax = max(freq.values())

    for x,y in sorted(freq.items(), key = lambda kv:(kv[1], kv[0]), reverse=True)[0:10]:
        stats.append([y,x])

    return [stats, hashTotalDups-blank_hash, hashMax]


if __name__ == '__main__':
    main()
