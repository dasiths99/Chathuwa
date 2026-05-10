import requests
import json
try:
    resp = requests.post('http://127.0.0.1:5005/api/test_api_call', json={'method':'GET','path':'/test','user_agent':'unit-test-bot','body':''}, timeout=5)
    print(resp.status_code)
    print(resp.text)
except Exception as e:
    print('ERROR', e)
