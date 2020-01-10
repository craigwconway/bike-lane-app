import os
import re

import boto3

from functions.report import ReportDAO
from functions.util import user_from_jwt, response


def handler(event, context):
    user = user_from_jwt(event['headers']['Authorization'])
    if(not user or 'sub' not in user.keys()):
        return response(401, 'Unauthorized {}'.format(user))

    table_name = os.environ['REPORT_TABLE']
    dynamo_table = boto3.resource('dynamodb').Table(table_name)
    reportDAO = ReportDAO(dynamo_table)

    event_key = '%s%s' % (event['httpMethod'], event['path'])

    try:
        if re.match('^GET/report/$', event_key):
            return response(200, reportDAO.by_user(user))
        if re.match('^POST/report/$', event_key):
            return response(200, reportDAO.save(event, user))
        if re.match('^GET/report/nearby/$', event_key):
            return response(200, reportDAO.by_location(event))
    except AssertionError:
        return response(401, 'Denied')
    except ValueError:
        return response(400, 'Say what')

    return response(404, 'Nope')


def handler_test(event, context):
    event_key = '%s%s' % (event['httpMethod'], event['path'])
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        'body': event_key
    }
