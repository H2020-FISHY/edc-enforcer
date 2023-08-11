import requests, sys

# nsf_to_generate = 'iptables'
# nsf_to_generate = 'xfrm'
# nsf_to_generate = 'stronGswAn'
# nsf_to_generate = 'genericpAckeTfilter'
# nsf_to_generate = 'etheReumWebAppAuthZ'
nsf_to_generate = None
if(len(sys.argv)>1):
    nsf_to_generate = sys.argv[1]


files = {'file':open('../src/newLanguage/NSFCatalogue.xml','rb')}
r = requests.post('http://127.0.0.1:6000/langGen', files=files, data={'upload':'Upload'})

if('File uploaded correctly' in r.text):
    if(nsf_to_generate is not None):
        r = requests.post('http://127.0.0.1:6000/langGen', data={'generate':'Generate', 'nsf':nsf_to_generate})
        start_idx = r.text.index('<h3>')
        end_idx = r.text.index('</h3>')
        output = r.text[start_idx+4:end_idx]
    else:
        r = requests.post('http://127.0.0.1:6000/langGen', data={'generateAll':'GenerateAll'})
        if(r.text.count('generated')>=6):
            output = 'All NSF Languages have been generated correctly.'

    print(r.text)
    print("###")
    print(output)