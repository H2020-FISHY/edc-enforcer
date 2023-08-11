import requests

files = {'file':open('../src/newConverter/definitivo.xmi','rb')}
r = requests.post('http://127.0.0.1:6000/converter', files=files, data={'upload':'Upload'})

if('File uploaded correctly' in r.text):
    r = requests.post('http://127.0.0.1:6000/converter', data={'generate':'Generate'})
    if('xsd' in r.text.lower()):
        print('Capability Data Model generated correctly.')