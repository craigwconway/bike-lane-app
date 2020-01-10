import os
import json
import uuid
import time
import decimal

import boto3
from boto3.dynamodb.conditions import Key, Attr

from functions.util import get_user, response


dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['PROFILE_TABLE'])


def validate(profile):
    valid_keys = ('notify_updates', 'notify_following', 'notify_new',
                  'id', 'username', 'created', 'updated')
    for key in profile.keys:
        if key not in valid_keys:
            return False
    return True


def create_or_update(profile, user):
    now = int(round(time.time() * 1000))
    try:
        if not 'id' in profile:
            profile['id'] = user['sub']
            profile['username'] = user['cognito:username']
        if 'id' in profile and profile['id'] != user['sub']:
            raise ValueError('Not authorized. ' + user['sub'])
        if not 'created' in profile:
            profile['created'] = now
            profile['updated'] = now
        else:
            profile['updated'] = now
        table.put_item(Item=profile)
    except Exception as e:
        return {'error': e}
    return profile


def handler(event, context):
    user = get_user(event['headers']['Authorization'])
    if(not user or 'sub' not in user.keys()):
        return response(401, 'Unauthorized')

    if(event['httpMethod'] == 'GET'):
        try:
            result = table.query(
                IndexName='id',
                KeyConditionExpression=Key('id').eq(user['sub'])
            )
            return response(200, result['Items'])
        except Exception as e:
            return response(500, str(e))

    elif(event['httpMethod'] == 'POST'):
        profile = json.loads(event['body'])
        if not validate(profile):
            return response(400, 'Invalid profile')
        profile = create_or_update(profile, user)
        if 'error' in profile:
            return response(500, profile['error'])
        return response(200, profile)

    return response(404, 'Not found')
