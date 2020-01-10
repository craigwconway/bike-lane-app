import pytest

from bikelaneapi.report import ReportDAO

VALID_REPORT = {
    'latitude': 0.0,
    'longitude': 0.0,
    'comment': 'i am a test',
    'severity': 0,
    'userId': 0,
    'username': 'test_foo'
}

INVALID_REPORT = {
    'foo': 'bar'
}


r = ReportDAO(None)


def test_validate():
    assert r.validate(VALID_REPORT)
    assert not r.validate(INVALID_REPORT)
    assert not r.validate({**VALID_REPORT, **INVALID_REPORT})
    assert not r.validate({})


def test_to_dynamo__from_dynamo():
    report = VALID_REPORT.copy()
    report['comment'] = ''
    r_dynamo = r.to_dynamo(report)
    assert isinstance(r_dynamo['latitude'], str)
    assert 'comment' not in r_dynamo
    f_dynamo = r.from_dynamo(r_dynamo)
    assert isinstance(r_dynamo['latitude'], float)
    assert 'comment' in f_dynamo
    assert f_dynamo['latitude'] == report['latitude']
