import os
import json
import uuid
import time
import decimal

import boto3
from boto3.dynamodb.conditions import Key, Attr

from util import get_user, response

EMPTY_VAL = '_'
QS = 'queryStringParameters'

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['REPORT_TABLE'])


def validate(report):
    valid_keys = ('latitude', 'longitude', 'comment', 'severity',
                  'id', 'userId', 'username', 'created', 'updated')
    for key in report.keys:
        if key not in valid_keys:
            return False
    return True


def to_dynamo(report):
    report['latitude'] = str(report['latitude'])
    report['longitude'] = str(report['longitude'])
    if(report['comment'] == ''):
        report['comment'] = EMPTY_VAL
    return report


def from_dynamo(report):
    report['latitude'] = float(report['latitude'])
    report['longitude'] = float(report['longitude'])
    if(report['comment'] == EMPTY_VAL):
        report['comment'] = ''
    return report


def create_or_update(report, user):
    now = int(round(time.time() * 1000))
    try:
        if not 'id' in report:
            report['id'] = str(uuid.uuid4())
            report['userId'] = user['sub']
            report['username'] = user['cognito:username']
        if 'userId' in report and report['userId'] != user['sub']:
            raise ValueError('Not authorized. ' + user['sub'])
        if not 'created' in report:
            report['created'] = now
            report['updated'] = now
        else:
            report['updated'] = now
        table.put_item(Item=to_dynamo(report))
    except Exception as e:
        return {'error': e}
    return report


def has_location(event):
    if(QS in event and event[QS]):
        for param in ['latitude', 'longitude', 'latitudeDelta', 'longitudeDelta']:
            if(param not in event[QS]):
                return False
        return True
    return False


def get_by_location(event):
    lat = decimal.Decimal(str(event[QS]['latitude']))
    lon = decimal.Decimal(str(event[QS]['longitude']))
    latDelta = decimal.Decimal(str(event[QS]['latitudeDelta']))
    lonDelta = decimal.Decimal(str(event[QS]['longitudeDelta']))
    try:
        result = table.scan(
            FilterExpression=Key('latitude').between(str(lat - latDelta/2), str(lat + latDelta/2)) &
            Key('longitude').between(
                str(lon + lonDelta/2), str(lon - lonDelta/2))
        )
        return response(200, result['Items'])
    except Exception as e:
        return response(500, str(e))


def get_by_user(user):
    try:
        result = table.query(
            IndexName='userId',
            KeyConditionExpression=Key('userId').eq(user['sub'])
        )
        return response(200, result['Items'])
    except Exception as e:
        return response(500, str(e))


def save_report(event, user):
    report = json.loads(event['body'])
    if not validate(report):
        return response(400, 'Invalid report')
    report = create_or_update(to_dynamo(report), user)
    if 'error' in report:
        return response(500, report['error'])
    return response(200, from_dynamo(report))


def handler(event, context):
    user = get_user(event['headers']['Authorization'])
    if(not user or 'sub' not in user.keys()):
        return response(401, 'Unauthorized')

    if(event['httpMethod'] == 'GET' and has_location(event)):
        get_by_location(event)
    elif(event['httpMethod'] == 'GET'):
        get_by_user(user)
    elif(event['httpMethod'] == 'POST'):
        save_report(event, user)

    return response(404, 'Not found')
