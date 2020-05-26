#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

'''
Simple wrapper for Paramiko SFTP client (see http://www.paramiko.org/)
'''

import getpass
import json
import os
import signal
import sys

import paramiko


VERSION='1.0'

# -----------------------------------------------------------------------------------------

def die(msg=None,rc=1):
    """
    Cleanly exits the program with an error message
    """

    if msg:
        print(msg)

    sys.exit(rc)

# ----------------------------------------------------------------------------

def isEmpty(s):
    if (s is None) or (len(s) <= 0):
        return True
    else:
        return False

# ----------------------------------------------------------------------------

def isNumberString(value):
    """
    Checks if value is a string that has only digits - possibly with leading '+' or '-'
    """
    if not value:
        return False

    sign = value[0]
    if (sign == '+') or (sign == '-'):
        if len(value) <= 1:
            return False

        absValue = value[1:]
        return absValue.isdigit()
    else:
        if len(value) <= 0:
            return False
        else:
            return value.isdigit()

def isNumberValue(value):
    return isinstance(value, (int, float))

# ----------------------------------------------------------------------------

def isFloatingPointString(value):
    """
    Checks if value is a string that has only digits - possibly with leading '+' or '-' - AND a single dot
    """
    if isEmpty(value):
        return False

    sign = value[0]
    if (sign == '+') or (sign == '-'):
        if len(value) <= 1:
            return False

        absValue = value[1:]
    else:
        absValue = value

    dotPos = absValue.find('.')
    # Must have a dot and it cannot be the last character
    if (dotPos < 0) or (dotPos == (len(absValue) - 1)):
        return False

    # Must have EXACTLY one dot
    dotCount = absValue.count('.')
    if dotCount != 1:
        return False

    # Make sure both sides of the dot are integer numbers
    intPart = absValue[0:dotPos]
    if not isNumberString(intPart):
        return False

    facPart = absValue[dotPos + 1:]
    # Do not allow 123.-5
    sign = facPart[0]
    if (sign == '+') or (sign == '-'):
        return False

    if not isNumberString(facPart):
        return False

    return True

# ----------------------------------------------------------------------------

def normalizeValue(value):
    """
    Checks if value is 'True', 'False' or all numeric and converts it accordingly
    Otherwise it just returns it

    Args:
        value (str) - String value
    """

    if not value:
        return value

    loCase = value.lower()
    if loCase == "none":
        return None
    elif loCase == "true":
        return True
    elif loCase == "false":
        return False
    elif isNumberString(loCase):
        return int(loCase)
    else:
        return value

# ----------------------------------------------------------------------------

def parseCommandLineArguments(args):
    """
    Parses an array of arguments having the format: --name=value. If
    only --name is provided then it is assumed to a TRUE boolean value.
    If the value is all digits, then it is assumed to be a number.

    If the same key is specified more than once, then a list of
    the accumulated values is created. The result is a dictionary
    with the names as the keys and value as their mapped values

    Args:
        args (str[]) - The command line arguments to parse
    """

    valsMap = {}
    if len(args) <= 0:
        return valsMap

    for item in args:
        if not item.startswith("--"):
            raise Exception("Missing option identifier: %s" % item)

        propPair = item[2:]     # strip the prefix
        sepPos = propPair.find('=')

        if sepPos == 0:
            raise Exception("Missing name: %s" % item)
        if sepPos >= (len(propPair) - 1):
            raise Exception("Missing value: %s" % item)

        propName = propPair
        propValue = None
        if sepPos < 0:
            propValue = True
        else:
            propName = propPair[0:sepPos]
            propValue = normalizeValue(propPair[sepPos + 1:])

        if propName in valsMap:
            curValue = valsMap[propName]
            if not isinstance(curValue, list):
                curValue = [ curValue ]
            curValue.append(propValue)
            valsMap[propName] = curValue
        else:
            valsMap[propName] = propValue

    return valsMap

# ----------------------------------------------------------------------------

def resolvePathVariables(path):
    """
    Expands ~/xxx and ${XXX} variables
    """
    if isEmpty(path):
        return path

    path = os.path.expanduser(path)
    path = os.path.expandvars(path)
    return path

# ----------------------------------------------------------------------------

def _decode_list(data):
    # can happen for internal sub-lists of objects
    if isinstance(data, dict):
        return _decode_dict(data)

    rv = []
    for item in data:
        if isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv

# ----------------------------------------------------------------------------

def _decode_dict(data):
    # can happen for internal sub-lists of objects
    if isinstance(data, list):
        return _decode_list(data)

    rv = {}
    for key, value in data.items():
        if isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value

    return rv

# ----------------------------------------------------------------------------

def loadJsonFile(configFile):
    if isEmpty(configFile):
        return {}

    with open(configFile) as config_file:
        return json.load(config_file, object_hook=_decode_dict);

# ----------------------------------------------------------------------------

def createSftpClient(args):
    host = args.get("host", "localhost")
    port = args.get("port", 22)
    username = args.get("username", None)
    if isEmpty(username):
        username = getpass.getuser()
    password = args.get("password", None)
    keyfile = args.get("keyFile", None)
    keytype = args.get("keyType", "RSA")

    sftp = None
    transport = None
    try:
        key = None
        if keyfile is not None:
            # Get private key used to authenticate user.
            if keytype == 'DSA':
                # The private key is a DSA type key.
                key = paramiko.DSSKey.from_private_key_file(keyfile)
            else:
                # The private key is a RSA type key.
                key = paramiko.RSAKey.from_private_key(keyfile)

        # Create Transport object using supplied method of authentication.
        transport = paramiko.Transport((host, port))
        transport.connect(None, username, password, key)
 
        sftp = paramiko.SFTPClient.from_transport(transport)
        return sftp
    except Exception as e:
        print('An error occurred creating SFTP client: %s: %s' % (e.__class__, e))

        if sftp is not None:
            try:
                sftp.close()
            except Exception as err:
                print('Failed to close SFTP client: %s: %s' % (err.__class__, err))

        if transport is not None:
            try:
                transport.close()
            except Exception as err:
                print('Failed to close transport: %s: %s' % (err.__class__, err))

        raise e
    
# =========================================================================================

def doList(sftp, curdir, argsList):
    dirPath = curdir;
    if not isEmpty(argsList):
        dirPath = argsList.pop(0)
        dirPath = dirPath.strip()
        dirPath = os.path.join(curdir, dirPath)

    # Also available: listdir_attr, listdir
    dirlist = sftp.listdir_iter(path=dirPath)
    for row in dirlist:
        # see https://docs.paramiko.org/en/2.6/api/sftp.html#paramiko.sftp_attr.SFTPAttributes
        print("    %s" % str(row))

def doChdir(sftp, homedir, curdir, argsList):
    dirPath = homedir
    if not isEmpty(argsList):
        dirPath = argsList.pop(0)
        dirPath = dirPath.strip()
        dirPath = os.path.join(curdir, dirPath)
    sftp.chdir(dirPath)

# ----------------------------------------------------------------------------

# see https://github.com/paramiko/paramiko/blob/master/demos/demo_sftp.py
# see https://docs.paramiko.org/en/2.6/api/sftp.html
def doSftp(sftp):
    homedir = sftp.normalize('.')
    sftp.chdir(homedir)
    
    while True:
        curdir = sftp.getcwd()
        sys.stdout.write("%s > " % curdir)
        sys.stdout.flush()
        l = sys.stdin.readline()
        l = l.strip()
    
        if isEmpty(l):
            continue
        
        argsList = l.split(' ')
        op = argsList.pop(0)
        
        if (op == "quit") or (op == "exit") or (op == "bye"):
            break
        elif (op == "ls") or (op == "list"):
            doList(sftp, curdir, argsList)
        elif (op == "cd"):
            doChdir(sftp, homedir, curdir, argsList)
        # TODO get_channel()
        #    show info using get_transport() on it
        #    get_security_options() on transport
        else:
            print("Unknown command: %s" % l)

def doMain(args):
    sftp = createSftpClient(args)
    try:
        doSftp(sftp);
    except Exception as e:
        print('An error occurred using the SFTP client: %s: %s' % (e.__class__, e))
        raise e
    finally:
        sftp.close()

#
# Usage: python3 sftpclient.py --arg1=value1 --arg2=value2 ...
#
# Where available arguments are:
#
#    * host - default=localhost
#    * port - default=22
#    * username - the login user - default=currently logged in user
#    * password - the password - can be omitted if key file used
#    * keyFile - path to key file
#    * keyType - type of key in file (RSA/DSA) - default=RSA
def main(args):
    if len(args) > 0:
        subArgs = parseCommandLineArguments(args)
    else:
        subArgs = {}
    doMain(subArgs)
    sys.exit(0)
    
# ----------------------------------------------------------------------------

def signal_handler(signal, frame):
    die('Exit due to Control+C')

if __name__ == "__main__":
    pyVersion = sys.version_info
    if pyVersion.major != 3:
        die("Major Python version must be 3.x: %s" % str(pyVersion))
    if pyVersion.minor < 0:
        print("Warning: minor Python version %s should be at least 3.0+" % str(pyVersion))

    signal.signal(signal.SIGINT, signal_handler)
    if os.name == 'nt':
        print("Use Ctrl+Break to stop the script")
    else:
        print("Use Ctrl+C to stop the script")
    main(sys.argv[1:])
