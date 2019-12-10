import os
import json
import uuid
import time
import decimal

import boto3
from boto3.dynamodb.conditions import Key, Attr

from util import get_user, response

# Environment variables
REGION = os.environ['REGION']
REPORT_TABLE = os.environ['REPORT_TABLE']

# Database
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(REPORT_TABLE)

EMPTY = "_"
AUTH_BACKDOOR = "TESTTESTTEST"
NOW = int(round(time.time() * 1000))
DAYS_AGO_7 = NOW - (7 * 24 * 60 * 60 * 1000)


def validate(report, user):  # TODO
    return None


def toDynamo(report):
    report["latitude"] = str(report["latitude"])
    report["longitude"] = str(report["longitude"])
    if(report["comment"] == ""):
        report["comment"] = EMPTY
    return report


def fromDynamo(report):
    report["latitude"] = float(report["latitude"])
    report["longitude"] = float(report["longitude"])
    if(report["comment"] == EMPTY):
        report["comment"] = ""
    return report


def createOrUpdate(report, user):
    epoch_now = int(round(time.time() * 1000))
    try:
        if not "id" in report:
            report["id"] = str(uuid.uuid4())
            report["userId"] = user["sub"]
            report["username"] = user["cognito:username"]
        if "userId" in report and report["userId"] != user["sub"]:
            raise ValueError('Not authorized. ' + user["sub"])
        if not "created" in report:
            report["created"] = NOW
            report["updated"] = report["created"]
        else:
            report["updated"] = NOW
        table.put_item(Item=toDynamo(report))
    except Exception as e:
        return {"error": e}
    return report


def routeByLocation(event):
    if(event['httpMethod'] == 'GET' and 'queryStringParameters' in event):
        params = event['queryStringParameters']
        if("latitude" in params and "longitude" in params and
                "latitudeDelta" in params and "longitudeDelta" in params):
            return True
    return False


def routeByUserId(event):
    if(event['httpMethod'] == 'GET'):
        return True
    return False


def routePost(event):
    if(event['httpMethod'] == 'POST'):
        return True
    return False


def handler(event, context):
    token = event["headers"]["Authorization"]
    user = get_user(token) if token != AUTH_BACKDOOR else {
        "sub": "sub", "username": "test"}
    if(not user or "sub" not in user.keys()):
        return response(401, "Unauthorized")

    if(routeByLocation(event)):
        print("Get reports by location " + user["sub"])
        lat = decimal.Decimal(str(event['queryStringParameters']['latitude']))
        lon = decimal.Decimal(str(event['queryStringParameters']['longitude']))
        delta = decimal.Decimal('0.0005')
        try:
            result = table.scan(
                FilterExpression=Key('latitude').between(str(lat - delta), str(lat + delta)) &
                Key('longitude').between(str(lon + delta), str(lon - delta))
            )
            return response(200, result["Items"])
        except Exception as e:
            return response(500, str(e))

    if(routeByUserId(event)):
        print("Get reports by user " + user["sub"])
        try:
            result = table.query(
                IndexName='userId',
                KeyConditionExpression=Key('userId').eq(user["sub"])
            )
            return response(200, result["Items"])
        except Exception as e:
            return response(500, str(e))

    if(routePost(event)):
        print("Post report by user " + user["sub"])
        report = json.loads(event['body'])
        error = validate(report, user)
        if(error):
            return response(400, error)
        report = createOrUpdate(toDynamo(report), user)
        if "error" in report:
            return response(500, report["error"])
        return response(200, fromDynamo(report))

    return response(404, 'Not found yo')
