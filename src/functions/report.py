import decimal
import json
import os
import re
import time
import uuid

from boto3.dynamodb.conditions import Key


class ReportDAO():

    def __init__(self, dynamo_table):
        super().__init__()
        self.table = dynamo_table

    def validate(self, report):
        req_keys = ('latitude', 'longitude', 'comment', 'severity',
                    'userId', 'username')
        opt_keys = ('id', 'created', 'updated')
        if not isinstance(report, dict):
            return False
        if len(report.keys()) < len(req_keys):
            return False
        for key in report.keys():
            if key not in req_keys + opt_keys:
                return False
        return True

    def to_dynamo(self, report):
        r = report.copy()
        r['latitude'] = str(r['latitude'])
        r['longitude'] = str(r['longitude'])
        if(r['comment'] == ''):
            del r['comment']
        return r

    def from_dynamo(self, report):
        report['latitude'] = float(report['latitude'])
        report['longitude'] = float(report['longitude'])
        if('comment' not in report.keys()):
            report['comment'] = ''
        return report

    def create_or_update(self, report, user):
        now = int(round(time.time() * 1000))
        if not 'id' in report:
            report['id'] = str(uuid.uuid4())
            report['userId'] = user['sub']
            report['username'] = user['cognito:username']
        if 'userId' in report and report['userId'] != user['sub']:
            raise AssertionError('User mismatch')
        if not 'created' in report:
            report['created'] = now
            report['updated'] = now
        else:
            report['updated'] = now
        self.table.put_item(Item=self.to_dynamo(report))
        return report

    def by_location(self, event):
        qs = 'queryStringParameters'
        lat = decimal.Decimal(str(event[qs]['latitude']))
        lon = decimal.Decimal(str(event[qs]['longitude']))
        latDelta = decimal.Decimal(str(event[qs]['latitudeDelta']))
        lonDelta = decimal.Decimal(str(event[qs]['longitudeDelta']))
        result = self.table.scan(
            FilterExpression=Key('latitude').between(str(lat - latDelta/2), str(lat + latDelta/2)) &
            Key('longitude').between(
                str(lon + lonDelta/2), str(lon - lonDelta/2))
        )
        return result['Items']

    def by_user(self, user):
        result = self.table.query(
            IndexName='userId',
            KeyConditionExpression=Key('userId').eq(user['sub'])
        )
        return result['Items']

    def save(self, event, user):
        report = json.loads(event['body'])
        if not self.validate(report):
            raise ValueError('Invalid Report')
        report = self.create_or_update(self.to_dynamo(report), user)
        return self.from_dynamo(report)
