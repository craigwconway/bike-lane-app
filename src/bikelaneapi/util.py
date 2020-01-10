import os
import json
import time
import decimal
import urllib.request

from jose import jwk, jwt
from jose.utils import base64url_decode


# https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(
    os.environ['REGION'], os.environ['USER_POOL'])
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']


def user_from_jwt(token):
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
    if not public_key.verify(message.encode('utf8'), decoded_signature):
        return False
    claims = jwt.get_unverified_claims(token)
    if time.time() > claims['exp']:
        return False
    print('Sub:{} Claim:{} ENV:{}'.format(
        claims['sub'], claims['aud'], os.environ['CLIENT_ID']))
    # if claims['aud'] != os.environ['CLIENT_ID']:
    #     return False
    return claims


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            return int(o)
        return super(DecimalEncoder, self).default(o)


def response(status=200, body=''):
    try:
        body = json.dumps(body, cls=DecimalEncoder)
    except:
        body = 'Error decoding json response'
        status = 500
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
        'body': body
    }
