import requests, sys

destination_nsf = ''


# files = {'file':open('../src/newTranslator/RuleInstances/IpTables_RuleInstance.xml','rb')}
# files = {'file':open('../src/newTranslator/RuleInstances/XFRM_RuleInstance.xml','rb')}
# files = {'file':open('../src/newTranslator/RuleInstances/Strongswan_RuleInstance.xml','rb')}
# files = {'file':open('../src/newTranslator/RuleInstances/genericPacketFilter_RuleInstance.xml','rb')}
# files = {'file':open('../src/newTranslator/RuleInstances/ethereumWebAppAuthz_RuleInstance.xml','rb')}
if(len(sys.argv)==2):
    input_path = sys.argv[1]
elif(len(sys.argv)==3):
    input_path = sys.argv[1]
    destination_nsf = sys.argv[2]
else:
    print('Please provide Rule Instance path and destination NSF (if needed).')
files = {'file':open(input_path,'rb')}
r = requests.post('http://127.0.0.1:6000/translator', files=files, data={'upload':'Upload'})

if('File uploaded correctly' in r.text):
    r = requests.post('http://127.0.0.1:6000/translator', data={'translate':'Translate', 'destnsf':destination_nsf})
    if not('html' in r.text):
        print(r.text)
        with open('output.txt', 'w') as file:
            file.write(r.text)
    else:
        start_idx = r.text.index('<h3>')
        end_idx = r.text.index('</h3>')
        output = r.text[start_idx+4:end_idx]
        print(output)
        with open('output.txt', 'w') as file:
            file.write(output)