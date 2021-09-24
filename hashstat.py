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
        ntds = []
        details = False
        top_hash = False
        top_cracked = False
        filename = ""
        file_data = ""

    my_ntds = ntds()
    my_ntds.details = options.details
    my_ntds.top_hash = options.top
    my_ntds.top_cracked = options.cracked
    my_ntds.filename = options.ntds

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
    print_ntds_stats(my_ntds)

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

def print_ntds_stats(ntds):

    # NT Password Hashes Breakdown #==================================================
    if ntds.nt_hashes:
        print(LIGHTGREEN+"\n[+] "+NOCOLOR, end = '')
        print("Total NT hashes:",end='')
        print(RED,len(ntds.nt_hashes),NOCOLOR)

        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
        print("Total unique NT hashes:",end='')
        print(RED,len(list(set(ntds.nt_hashes))),NOCOLOR)

        stats, nt_total, nt_max = get_top_ten_reused_hashes(ntds.nt_hashes)
        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
        print("Most reused NT hash was used:",end='')
        print(RED,nt_max,NOCOLOR)
        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
        print("Total # of duplicate NT hashes:",end='')
        print(RED,nt_total,NOCOLOR)
        print()

        # NT Top Hashes Breakdown #===================================================
        if ntds.top_hash:
            print(GREEN,"Top Ten duplicate NT hashes:",NOCOLOR)
            print(YELLOW+"-------------------------------------------------"+NOCOLOR)
            print_top_ten(stats, len(ntds.nt_hashes))

        # NT Passwords Cracked Hashes Breakdown #=====================================
        if ntds.top_cracked:
            #print("Trying to see Cracked shit!")
            cracked_hash_stats(ntds.nt_hashes,"nt",ntds.filename)

    # LM Password Hashes Breakdown #==================================================
    if ntds.lm_hashes:
        print(LIGHTGREEN+"[+] "+NOCOLOR, end='')
        print("Total accounts with LM hashes:",end='')
        print(RED,len(ntds.lm_hashes),NOCOLOR)

        lm_total = []
        
        for s in ntds.lm_hashes:
            s1 = s[:len(s)//2]
            s2 = s[len(s)//2:]
            lm_total += [s1]
            lm_total += [s2]
            myset = set(lm_total)
            # .discard() only removed if value exist vs .remove() which rasies error
            myset.discard("aad3b435b51404ee") 

        # Printing output
        print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
        print("Total LM hashes:",end='')
        print(RED,len(list(set(myset))),NOCOLOR)

        print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
        print("Total unique LM hash passwords:",end='')
        print(RED,len(list(set(ntds.lm_hashes))),NOCOLOR)

        # pipal style get dup values of list
        stats, lm_total, lm_max = get_top_ten_reused_hashes(ntds.lm_hashes)

        print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
        print("Most reused LM hash password was used:",end='')
        print(RED,lm_max,NOCOLOR)
        print(LIGHTGREEN+"[+] "+NOCOLOR,end='')
        print("Total # of duplicate LM hashes:",end='')
        print(RED,lm_total,NOCOLOR)
        print()

        if ntds.top_hash:
            print(GREEN,"Top Ten duplicate LM hashes:",NOCOLOR)
            print(YELLOW+"-------------------------------------------------"+NOCOLOR)
            print_top_ten(stats, len(ntds.lm_hashes))

        if ntds.top_cracked:
            cracked_hash_stats(ntds.lm_hashes,"lm",ntds.filename)
    else:
        print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
        print("Found no LM hashes in this file\n")

def cracked_hash_stats(hashes, type_hash, filename):
    # This function takes a list 

    john_cracked = []
    domains = []
    passwords = []
    dups = []
    hash_format = "--format="+type_hash

    # get cracked hashes from john the ripper
    #process_john = subprocess.Popen(('john', '--show', hash_format, "/tmp/hashstat"),
    #        stdout=subprocess.PIPE, shell=False)
    process_john = subprocess.Popen(('john', '--show', hash_format, filename), 
            stdout=subprocess.PIPE, shell=False)
    output = subprocess.check_output(('grep', ':::'), 
            stdin=process_john.stdout, shell=False).decode("utf-8")
    process_john.stdout.close()

    # clean ntds
    # convert strings to list
    john_cracked = output.split('\n')
    # delete empty list items
    john_cracked = [ x for x in john_cracked if x ]

    # if lm hashes delete empty lm hashes
    if type_hash == "lm":
        john_cracked = [ x for x in john_cracked if 'aad3b435b51404eeaad3b435b51404ee' not in x.lower() ]

    # create lists of domains, passwords, and dups from list of
    # stings that look like this: "domain\user:pass:id:lm:nt:::"
    for item in john_cracked:
        # debugging
        # print(item)
        if '\\' not in item:
            domain = ""
            username, password, rid, lm, nt = item.split(':', 4)
            passwords.append(password)
            if username.lower() == password.lower():
                dups.append(username)
        else:
            domain,single_hash = item.split('\\', 1)
            username, password, rid, lm, nt = single_hash.split(':', 4)
            passwords.append(password)
            if username.lower() == password.lower():
                dups.append(username)

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
    print(RED,len(dups),NOCOLOR)
    print(LIGHTGREEN+"[+] "+NOCOLOR, end = '')
    print("Unique number of domains found in ntds file:",end='')
    print(RED,len(domains),NOCOLOR)

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

    hashMax = max(freq.values())

    # freq = {'f0c99bb71ee888f1ebade3ec1090c5f0': 1, '93f6796100b7773d1d71060d896b7a46': 1, '82175fce03b77644417eaf50cfac29c3': 1}
    # freq is a two value dictionary.

    for x,y in sorted(freq.items(), key = lambda kv:(kv[1], kv[0]), reverse=True)[0:10]:
        stats.append([y,x])

    return [stats, hashTotalDups-blank_hash, hashMax]


if __name__ == '__main__':
    main()
