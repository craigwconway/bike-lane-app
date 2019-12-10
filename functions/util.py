import os
import json
import time
import decimal
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

# Environment variables
REGION = os.environ['REGION']
userpool_id = os.environ['userpool_id']
app_client_id = os.environ['app_client_id']

# download only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(
    REGION, userpool_id)
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']


# https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py
def get_user(token):
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        return False
    public_key = jwk.construct(keys[key_index])
    message, encoded_signature = str(token).rsplit('.', 1)
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        return False
    claims = jwt.get_unverified_claims(token)
    if time.time() > claims['exp']:
        return False
    if claims['aud'] != app_client_id:
        return False
    return claims


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)


def response(status=200, body=''):
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        "body": json.dumps(body, cls=DecimalEncoder),
    }


def dump(obj):
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))
