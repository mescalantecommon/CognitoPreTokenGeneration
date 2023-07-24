from __future__ import print_function
from datetime import datetime
import pymysql
import pymysql.cursors
import boto3
import json
import base64
import os
import botocore.exceptions
from botocore.config import Config

class UserInfo:
    def __init__(self, DeviceKey, DeviceName,DeviceIP,DeviceLastAuthenticatedDate,UserName,ApplicantId,RecommenderId,UserProfileId):
        #self.DeviceKey = DeviceKey
        self.ApplicantId = ApplicantId
        self.RecommenderId = RecommenderId
        self.UserProfileId = UserProfileId
        self.UserName = UserName
        self.DeviceName = DeviceName
        self.DeviceIP = DeviceIP
        self.DeviceLastAuthenticatedDate = DeviceLastAuthenticatedDate
        
        

def dateconverter(o):
    if isinstance(o, datetime):
        return o.__repr__()
        
def lambda_handler(event, context):
    print('event: ')
    print(event)
    if event['triggerSource'] == 'TokenGeneration_RefreshTokens':
        #decrpt the connection string
        session = boto3.session.Session()
        kms = session.client('kms')
        encrypted_password = os.environ['secrets']
        binary_data = base64.b64decode(encrypted_password)
        meta = kms.decrypt(CiphertextBlob=binary_data)
        plaintext = meta[u'Plaintext']
        #print(plaintext)
        secrets = json.loads(plaintext.decode())
        #print(secrets)

        # creating list        
        list = []  
        #if(event['request']['newDeviceUsed'] != True):
        response = None
        config = Config(
           retries = {
              'max_attempts': 5,
              'mode': 'standard'
           }
        )
        client = boto3.client('cognito-idp', config=config)
        try:
            response = client.admin_list_devices(
            UserPoolId= event['userPoolId'], 
            Username= event['userName']
            )
        except botocore.exceptions.ClientError as err:
            print('Error Message: {}'.format(err.response['Error']['Message']))
            print('Error code: {}'.format(err.response['Error']['Code']))
            print('Request ID: {}'.format(err.response['ResponseMetadata']['RequestId']))
            print('Http code: {}'.format(err.response['ResponseMetadata']['HTTPStatusCode']))
            print('RetryAttempts: {}'.format(err.response['ResponseMetadata']['RetryAttempts']))
            
        print('response[Devices]: ')
        print(response['Devices'])
        Ks=response['Devices']
        for Device in Ks:
            DeviceKey=Device['DeviceKey']
            DeviceLastAuthenticatedDate=Device['DeviceLastAuthenticatedDate']
            for DeviceAtt in Device['DeviceAttributes']:
                if DeviceAtt['Name'] == 'device_name':
                    DeviceName=DeviceAtt['Value']
                if DeviceAtt['Name'] == 'last_ip_used':
                    DeviceIP=DeviceAtt['Value']

            ApplicantId = None
            RecommenderId = None
            UserProfileId = None

            if event['userPoolId'] == secrets["CognitoUserPoolId_Applicant"]:
                ApplicantId=event['request']['userAttributes']['custom:APPLICANTID']
                
            if event['userPoolId'] == secrets["CognitoUserPoolId_Recommender"]:
                RecommenderId=event['request']['userAttributes']['custom:RECOMMENDERID']

            if event['userPoolId'] == secrets["CognitoUserPoolId_Member"]:
                UserProfileId=event['request']['userAttributes']['custom:USERPROFILEID']

            list.append(UserInfo(DeviceKey, DeviceName,DeviceIP,DeviceLastAuthenticatedDate,event['request']['userAttributes']['preferred_username'],ApplicantId,RecommenderId,UserProfileId))
        #else:
            #list.append(UserInfo('', '','',datetime.utcnow(),event['request']['userAttributes']['preferred_username'],event['request']['userAttributes']['custom:APPLICANTID']))
        
        list=sorted(list, key=lambda d: d.DeviceLastAuthenticatedDate, reverse=True)
        print('list: ')
        print(json.dumps(list[0].__dict__, default = dateconverter))
    
        
        # Open database connection
        # Connect to the database
        connection = pymysql.connect(host=secrets["ConnectionString"]["server"],
                                    user=secrets["ConnectionString"]["userId"],
                                    password=secrets["ConnectionString"]["password"],
                                    db=secrets["ConnectionString"]["database"],
                                    cursorclass=pymysql.cursors.DictCursor)

        try:
            with connection.cursor() as cursor:
                sql = "Insert into SessionLog(`ApplicantId`,`RecommenderId`,`UserProfileId`, `sessionStartDt`, `IpInfo`, `browser`, `Server`, `UpdatedBy`) values(%s,%s,%s,%s,%s,%s,%s,%s)"
                cursor.execute(sql, (list[0].ApplicantId, list[0].RecommenderId, list[0].UserProfileId, list[0].DeviceLastAuthenticatedDate, list[0].DeviceIP, list[0].DeviceName, event['userPoolId'],"0"))
                # Commit your changes in the database
                connection.commit()
        finally:
            connection.close()

    return event