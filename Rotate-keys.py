import boto3
import datetime
import pytz
import os
import logging
from CheckAccounts import getEmails, getPublicKeys, checkUsers
from Whitelist import notWhitelisted
from AssumeRole import assumeClient, assume, loadAccountConfig
from SendEmail import sendEmail

######################################################################################################
#test&debug
testFlag = True                         #True: does not do Delete or Create operations. WILL SEND EMAIL NOTIFICATIONS
p2c = True                              #True: print to console for debuging/testing. Everything always goes to log file
testAccount = "TEST-Account"                 #Testing account name for current account (in AccountInfo.json)
                                        #IAM user configured must have access to IAM in account. Only works with loopAccounts = False

#run script variables
production = False                      #True: sends emails and other production operations
loopAccounts = False                    #True: loop through all accounts & False: loop users in current account (Production must also be True)
notifyOPS = True                        #True: sends email to OPS for every account not in whitelist or doesn't have GPG key properly configured

#production variables
logsToBucket = True                     #True: will upload log file to 'keyBucket' with keys for review and storage
acctsFromBucket = True                  #True: will enable downloading of IAMAccountList.json file from 'keyBucket' otherwise use local copy
keyBucket = "<<bucket name>>"          #bucket name for saving encrypted keys and logs
notifyEmail = "me@email.com"        #default email address for sending/recieving IAM Information notifications

#script variables
k1Date = datetime.datetime.utcnow()
k2Date = datetime.datetime.utcnow()
######################################################################################################

logDir=os.path.dirname(os.path.realpath(__file__))
workingDir=os.path.dirname(os.path.realpath(__file__))

# // TODO: ec2-user on CRON not allowed permissions to log dir - 31Mar
#if production and loopAccounts and not testFlag:
#    logDir='/var/log'

logging.basicConfig(filename=logDir + '/IAM-Rotate-Keys.log', level=logging.INFO, format='%(asctime)s : %(name)s : %(levelname)s : %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

# sends notification to team that something went wrong with an IAM User
# Could be that IAM account is not listed in Accounts List JSON file
# GPG Key is not properly imported on CRON Server
# Public Key email address in Accounts List does not match their Public Key
def notifyMissing(username, account):
    message = ("\n\nThe following user is missing a Public Key for Encryption or not in Whitelist:" + 
            "\nIAM User: " + username +
            "\nAccount: " + account +
            "\n\nEnsure key is imported using GPG on CRON Server, User is listed in IAM Account list, and/or their Public Key email is correctly present in IAM Account List.\n\n")

    recipents = [notifyEmail]
    if production:
        sendEmail(
            recipents, 
            'noreply@email.com', 
            'TEAM MESSAGE: MISSING INFORMATION FOR IAM USER',
            message,
            "plain"
        )
    if p2c and not production: print("SEND TO: " + str(recipents) + "\nMESSAGE: " + message)

# sends notification to customer that a new key has been created for use
# and that the existing key they should already be using will be deleted in 3 months.
def notifyKey(keyID, username, account, filename):
    message = ("\n\nThis is a IAM Access ID expiration notification for the following IAM Key Pair:" + 
            "\n\nAccess ID: " + keyID + 
            "\nIAM User: " + username +
            "\nAccount: " + account +
            "\n\nThis key pair will be deleted in 3 Months." +
            "\n\nYour new encrypted key pair can be found here: https://s3-us-west-2.amazonaws.com/" + keyBucket + "/" + filename +
            "\n\nPlease make the necessary changes to your new key to prevent any downtime in production.\n\n")

    recipents = getEmails(account, username)
    if production:
        sendEmail(
            recipents, 
            'noreply@email.com', 
            'TEAM MESSAGE: KEY ROTATION NOTIFICATION',
            message,
            "plain"
        )

    if p2c and not production: print("SEND TO: " + str(recipents) + "\nMESSAGE: " + message)
    logging.info("ACCESS ID NOTIFICATION. Key: " + keyID + " for user: " + username + " in account: " + account + " will be deleted in 3 months")
    if p2c: print("ACCESS ID NOTIFICATION. Key: " + keyID + " for user: " + username + " in account: " + account + " will be deleted in 3 months")

# sends notification to customer that a specifie key has been deleted
def notifyDelete(keyID, username, account):
    message = ("\n\nThis is a IAM Access ID deletion notification for the following IAM Key Pair:" + 
            "\n\nAccess ID: " + keyID + 
            "\nIAM User: " + username +
            "\nAccount: " + account +
            "\n\nThis key pair WAS DELETED on: " + str(datetime.datetime.utcnow()) +
            "\n\n\n\n")

    recipents = getEmails(account, username)
    if production:
        sendEmail(
            recipents, 
            'noreply@email.com', 
            'TEAM MESSAGE: KEY DELETION NOTIFICATION',
            message,
            "plain"
        )

# creates AccessID/Secret Pair based on information passed from checkKeys
# encrypts keyfile and uploads to S3 bucket for distribution
def createKey(username, client, account, S3, notifyID):
    if not testFlag: response = client.create_access_key(UserName=username)
    if testFlag: logging.info(" !!! THIS WAS A ROTATION TEST NOTHING WAS CREATED !!! ")
    if not testFlag: access_key = response['AccessKey'] #access_key['AccessKeyId'] + "\nSecret Key: " + access_key['SecretAccessKey'])
    if not testFlag: logging.info("KEY CREATION CONFIRMATION. AccessID : " + access_key['AccessKeyId'] + " created for user: " + username + " in account: " + account + ".")
    if p2c and not testFlag: print("KEY CREATION CONFIRMATION. AccessID : " + access_key['AccessKeyId'] + " created for user: " + username + " in account: " + account + ".")
    
    #create key file for encryption and TX to S3 Bucket
    if not testFlag: filename = str(account + '-' + username + '-' + access_key['AccessKeyId'] + '.csv')
    if testFlag: filename = str(account + '-' + username + '-TEST-FILE.csv')
    contents = open(filename, 'w')
    contents.write('Account, User, AccessID, AccessKey, Created\n')
    if not testFlag: contents.write(account + ',' + username + ',' + access_key['AccessKeyId'] + ',' + access_key['SecretAccessKey'] + ',' + str(access_key['CreateDate']) )
    contents.close()
    logging.info("KEY FILE CREATED for user: " + username + ".")
    if p2c: print("KEY FILE CREATED for user: " + username + ".")

    #Encrypt File with TEAM Public Key(s) and Customer Pubic Key(s)
    os.system("gpg " + getPublicKeys(account, username) + " --encrypt " + filename)

    #place excrypted key file in bucket if file exists.
    #if file does not exist then there is a public key missing. NOTIFY TEAM
    encryptedFilename = filename + '.gpg'

    try:
        S3.upload_file(encryptedFilename, keyBucket, encryptedFilename)
        if not testFlag: logging.info("ACCESS ID PLACEMENT. Key: " + access_key['AccessKeyId'] + " for user: " + username + " in account: " + account + " placed in " + keyBucket + " bucket.")
        if p2c and not testFlag: print("ACCESS ID PLACEMENT. Key: " + access_key['AccessKeyId'] + " for user: " + username + " in account: " + account + " placed in " + keyBucket + " bucket.")
        #send notification email to user with deletion info and new encrypted key
        notifyKey(notifyID, username, account, encryptedFilename)
    except:
        logging.info("ACCESS ID NOT ENCRYPTED for user: " + username + ". MISSING A PUBLIC KEY REQUIRED FOR ENCRYPTION")
        if p2c: print("ACCESS ID NOT ENCRYPTED for user: " + username + ". MISSING A PUBLIC KEY REQUIRED FOR ENCRYPTION")
        #send notification email to TEAM with no public key alert
        if notifyOPS: notifyMissing(username, account)

# deletes AccessID/Secret Pair based on information passed from checkKeys
def deleteKey(keyID, username, client, account, S3, notifyID):
    if not testFlag: client.delete_access_key(AccessKeyId=keyID, UserName=username)
    if testFlag: logging.info(" !!! THIS WAS A ROTATION TEST NOTHING WAS DELETED !!! ")
    logging.info("DELETION CONFIRMATION for AccessID : " + keyID + " for user: " + username + " in account: " + account + " has been deleted.")
    if p2c: print("DELETION CONFIRMATION for AccessID : " + keyID + " for user: " + username + " in account: " + account + " has been deleted.")
    notifyDelete(keyID, username, account)

    # delete encrypted file from s3 bucket
    filename = str(account + '-' + username + '-' + keyID + '.csv')
    S3.delete_object(Bucket=keyBucket, Key=filename)
    S3.delete_object(Bucket=keyBucket, Key=filename + '.gpg')
    logging.info("KEY FILE DELETED FROM S3 BUCKET: " + keyBucket + " for " + username + " in account: " + account + ".")
    if p2c: print("KEY FILE DELETED FROM S3 BUCKET: " + keyBucket + " for " + username + " in account: " + account + ".")

    logging.info("CREATING NEW ACCESS ID for username: " + username + " in account: " + account + ".")
    if p2c: print("CREATING NEW ACCESS ID for username: " + username + " in account: " + account + ".")
    createKey(username, client, account, S3, notifyID)

#Checks key information for passed in IAM USER 
#Collect Key IDs and Created Dates
#Assumes 0-2 Keys per IAM USER   
def checkKeys(client, user, account, S3):
    keyCnt = 0
    key1Date = k1Date.replace(tzinfo=pytz.UTC)
    key2Date = k2Date.replace(tzinfo=pytz.UTC)
    logging.info("CHECKING ACCESS ID(S) for IAM User: " + user.user_name + " in account: " + account)
    if p2c: print("CHECKING ACCESS ID(S) for IAM User: " + user.user_name + " in account: " + account)
    Metadata = client.list_access_keys(UserName=user.user_name)
    if Metadata['AccessKeyMetadata']:
        for key in user.access_keys.all():
            AccessId = key.access_key_id
            Created = key.create_date
            keyCnt = keyCnt + 1
            notifyID = AccessId

            if keyCnt == 1:
                key1Date = Created
                key1 = AccessId
                notifyID = AccessId
            if keyCnt == 2:
                key2 = AccessId
                key2Date = Created

            #check which key is older. Assumes no more than 2 keys per IAM USER
            if key2Date < key1Date:
                deleteID = key2 #key2 is older
                notifyID = key1
            else:
                deleteID = key1

        #If IAM User only has 1 Key, Create new key
        #Else Delete older key and Create new key
        if keyCnt == 1:
            logging.info("IAM USER: " + user.user_name + " has " + str(keyCnt) + " key(s).")
            if p2c: print("IAM USER: " + user.user_name + " has " + str(keyCnt) + " key(s).")
            logging.info("CREATING NEW ACCESS ID for username: " + user.user_name + " in account: " + account + ".")
            if p2c: print("CREATING NEW ACCESS ID for username: " + user.user_name + " in account: " + account + ".")
            createKey(user.user_name, client, account, S3, notifyID)
        elif keyCnt > 1:
            logging.info("IAM USER: " + user.user_name + " has " + str(keyCnt) + " key(s).")
            if p2c: print("IAM USER: " + user.user_name + " has " + str(keyCnt) + " key(s).")
            logging.info("DELETING EXPIRED ACCESS ID: " + deleteID + " for username: " + user.user_name + " in account: " + account + ".")
            if p2c: print("DELETING EXPIRED ACCESS ID: " + deleteID + " for username: " + user.user_name + " in account: " + account + ".")
            deleteKey(deleteID, user.user_name, client, account, S3, notifyID)

        if p2c: print("KEY ROTATION COMPLETE for user: " + user.user_name + " in account " + account + ".")
        logging.info("KEY ROTATION COMPLETE for user: " + user.user_name + " in account " + account + ".")

    #If User had no keys
    if keyCnt == 0:
        logging.info("IAM USER: " + user.user_name + " had 0 keys.")
        if p2c: print("IAM USER: " + user.user_name + " had 0 keys.")

#deletes all locally created encrypted/un-encrypted csv/gpg files at end of script
def clearTmp():
    filelist = [ f for f in os.listdir(".") if f.endswith(".csv") ]
    for f in filelist:
        os.remove(f)
    filelist = [ f for f in os.listdir(".") if f.endswith(".gpg") ]
    for f in filelist:
        os.remove(f)
    if p2c: print("LOCAL TMP ACCESS IDs HAVE BEEN REMOVED.")
    logging.info("LOCAL TMP ACCESS IDs HAVE BEEN REMOVED.")

#downloads IAM account listing from s3 bucket if enabled
def getAccountsFile(S3):
    S3.Bucket(keyBucket).download_file('IAMAccountList.json', 'IAMAccountList.json')

#uploads logs to S3 bucket if enabled
def uploadLogs(S3):
    S3.upload_file('IAM-Rotate-Keys.log', keyBucket, 'IAM-Rotate-Keys-' + str(datetime.datetime.utcnow()) + '.log')

#runs script across all accounts with role from AssumeRole.py
def loopAllAccounts():
    for account in loadAccountConfig():
        client = assumeClient(account, "iam")
        resource = assume(account, "iam")
        S3 = boto3.client("s3")
        if acctsFromBucket: getAccountsFile(boto3.resource('s3'))
        for user in resource.users.all():
            if checkUsers(account, user.user_name):
                checkKeys(client, user, account, S3)
            else:
                if notifyOPS and notWhitelisted(user.user_name):
                    notifyMissing(user.user_name, account)
    if p2c: print("KEY ROTATION COMPLETE for all IAM Users in account: " + account + ".")
    logging.info("KEY ROTATION COMPLETE for all IAM User in account: " + account + ".")
    if logsToBucket: uploadLogs(S3)

#runs script with current AWS CLI credentials on static 'testAccount'
def currentAccount():
    client = boto3.client("iam")
    resource = boto3.resource('iam')
    S3 = boto3.client("s3")
    if acctsFromBucket: getAccountsFile(boto3.resource('s3'))
    for user in resource.users.all():
        if checkUsers(testAccount, user.user_name):
            checkKeys(client, user, testAccount, S3)
        else:
            if notifyOPS: notifyMissing(user.user_name, testAccount)
    if p2c: print("KEY ROTATION COMPLETE for all IAM User(s) in account: " + testAccount + ".")
    logging.info("KEY ROTATION COMPLETE for all IAM User(s) in account: " + testAccount + ".")
    if logsToBucket: uploadLogs(S3)

# START OF SCRIPT
# must both be set to true for running across all AWS accounts and in production
# otherwise script will run with current credentials required for running on static 'testAccount'
if loopAccounts and production:
    if testFlag: logging.info(" !!! THIS WAS A ROTATION TEST MODIFICATION OPREATIONS ARE DISABLED !!! ")
    logging.info("Starting key rotation across all accounts")
    if p2c: print("Starting key rotation across all accounts")
    loopAllAccounts() 
    clearTmp()
else:
    if testFlag: logging.info(" !!! THIS WAS A ROTATION TEST MODIFICATION OPREATIONS ARE DISABLED !!! ")
    logging.info("Starting key rotation for account: " + testAccount)
    if p2c: print("Starting key rotation for account: " + testAccount)
    currentAccount()
    clearTmp()
