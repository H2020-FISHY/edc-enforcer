import json
import uuid
import sys
from datetime import datetime
import pika


def create_file_metadata(file_content):
    command_list = []
    metadata_list = []
    action = ''
    ip = ''
    wid = ''
    did = ''
    lines = file_content.split('\n')
    for l in lines:

        if(('DID' in l or 'WID') and 'BAN' in l):
            # Case 1)
            # {
            # "action": "ban_wid",
            # "wid": "0x38fE4036a3cB5fF2C3f4bF4c5D400f6c57016Dd0",
            # "command": "BAN WID:0x38fE4036a3cB5fF2C3f4bF4c5D400f6c57016Dd0"
            # }
            if('WID' in l):
                action = 'ban_wid'
                if(wid==''):
                    wid = l.split('WID:',1)[1].split(' ',1)[0]
                metadata = {
                    "action": action,
                    "wid": wid,
                    "command": l
                }
                metadata_list.append(metadata)

            # Case 2)
            # {
            # "action": "ban_did",
            # "did": "CnWZ2pmT6adiW8YEg2znCT",
            # "command": "BAN DID:CnWZ2pmT6adiW8YEg2znCT"
            # }
            if('DID' in l):
                action = 'ban_did'
                if(did==''):
                    did = l.split('DID:',1)[1].split(' ',1)[0]
                metadata = {
                    "action": action,
                    "did": did,
                    "command": l
                }
                metadata_list.append(metadata)
        # Case 3)
        # {
        # "action": "ban_ip",
        # "ip": "11.11.11.11",
        # "command": "iptables -A INPUT -s 11.11.11.11 -j DROP"
        # }
        if('iptables' in l and 'DROP' in l):
            if(action==''):
                action = 'ban_ip'
            if(ip==''):
                ip = l.split('-s ',1)[1].split(' ',1)[0]
            command_list.append(l)
            metadata = {
            "action": action,
            "ip": ip,
            "command": command_list
            }
    if(len(metadata_list) == 0):
        return metadata
    else:
        return metadata_list


if(len(sys.argv)==2):
    file_path = sys.argv[1]
elif(len(sys.argv)==1):
    print('Please provide path of the file to send.')
    sys.exit()

server = 'fishy-rabbitmq.lab.synelixis.com'
port = 35672
credentials = pika.PlainCredentials("user", "mBmT4wfV")

f = open(file_path)
if f is not None:
    file_content = f.read()
if file_content is not None or not file_content=='':
    payload = create_file_metadata(file_content)
    # payload = {
    #     "uuid": str(uuid.uuid4()),
    #     "timestamp": str(datetime.utcnow()),
    #     "type": 4,
    #     "metadata": metadata
    # }

    connection = pika.BlockingConnection(pika.ConnectionParameters(
        host=server,
        port=port,
        credentials=credentials)
    )
    channel = connection.channel()
    if(not isinstance(payload, list)):
        payload = [payload]
    for p in payload:
        channel.basic_publish(exchange='events', routing_key='', body=json.dumps(p))
        print(" [x] Sent payload.")
    connection.close()
else:
    print("Error while reading input file.")
