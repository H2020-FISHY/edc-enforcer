import pika, sys, os
import json, base64
from xml.dom import minidom
import requests
from datetime import datetime

from rabbit_producer import RMQproducer


def lowerCaseXMLTags(xml_string):

        # parse the xml string
        dom = minidom.parseString(xml_string)

        # iterate through all elements in the xml
        for node in dom.getElementsByTagName("*"):
            # change the first letter of the tag name to lowercase
            node.tagName = node.tagName[0].lower() + node.tagName[1:]

        # return the modified xml as a string
        return dom.toxml()

class RMQsubscriber:

    def __init__(self, queueName, bindingKey, config):

        self.queueName = queueName
        self.bindingKey = bindingKey
        self.config = config
        self.connection = self._create_connection()

    def __del__(self):
        if self.connection.is_open:
            self.connection.close()

    def _create_connection(self):

        credentials = pika.PlainCredentials(self.config['login'], self.config['password'])
        parameters = pika.ConnectionParameters(host=self.config['host'],
                          port=self.config['port'],
                          virtual_host='/',
                          credentials=credentials)
        connection = pika.BlockingConnection(parameters)

        return connection

    def on_message_callback(self, channel, method, properties, body):

        print(" [x] Received %r" % body)

        mlsp_filename = "mlsp.xml"

        message = json.loads(body.decode('utf-8'))

        if message["task_type"] != "mspl.create":
            print("Ignoring message of type: " + message["task_type"])
            return

        message = message["details"]
        mspl_id_cr = message["id"]

        message_data = json.loads(message["data"].encode('utf-8'))
        if message_data["mode"] == "standalone":
            print("Ignoring standalone notification")
            return

        base64_hspl_string: str = message_data["payload"]

        mlsp = base64.b64decode(base64_hspl_string.encode("utf-8")).decode('utf-8')

        with open(mlsp_filename, 'w') as file:
            # Write the string to the file
            file.write(mlsp)

        with open(mlsp_filename, "rb") as file:
            files = {"file": file}
            r = requests.post(f"http://localhost:6000/translator", files=files, data={"upload":"Upload"})

        output = None
        if("File uploaded correctly" in r.text):
            r = requests.post(f"http://localhost:6000/translator", data={"translate":"Translate", "destnsf":""})
            if r.status_code == 500:
                return "An error occurred"
            if not("html" in r.text):
                output = r.text
            else:
                start_idx = r.text.index("<h3>")
                end_idx = r.text.index("</h3>")
                output = r.text[start_idx+4:end_idx]

        final_output = output.splitlines()
        print(final_output)

        ### Push to Central Repository

        url = "https://" + "fishy.xlab.si/tar/api/configurations"

        headers = {'Content-Type': 'application/json'}

        base64_llsp_strings = []
        for el in final_output:
            base64_llsp_strings.append(base64.b64encode(el.encode('utf-8')).decode('utf-8'))

        # Get the current UTC time
        now_utc = datetime.utcnow()
        # Format the time as a string in ISO 8601 format with milliseconds and a 'Z' suffix
        time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        data = {"payload": base64_llsp_strings, "mode": "asynchronous"}

        message = {"source": "edc-secap", "data": json.dumps(data), "status": "both", "timestamp": time_str, "mspl_id": mspl_id_cr}

        raw_response = requests.post(url, headers=headers, data=json.dumps(message))
        response = json.loads(raw_response.text)

        if raw_response.status_code == 201:
            response_data = raw_response.json()
            print("Configuration loaded on CR!")
            print(response_data)
        else:
            print("Error:", raw_response.status_code)

        channel.basic_ack(delivery_tag=method.delivery_tag)

        ### Directly producing on RabbitMQ
        # queueName = 'IROQueue'
        # routingKey = 'mlsp'
        # notification_producer_config = {'host': 'fishymq.xlab.si',
        #                                 'port': 45672,
        #                                 'exchange' : 'tasks',
        #                                 'login':'tubs',
        #                                 'password':'sbut'}

        # init_rabbit = RMQproducer(routingKey, notification_producer_config)
        # base64_llsp_strings = []
        # for el in final_output:
        #     base64_llsp_strings.append(base64.b64encode(el.encode('utf-8')).decode('utf-8'))
        # message = {"llsp": base64_llsp_strings}
        # init_rabbit.send_message(message)

    def setup(self):

        channel = self.connection.channel()

        # This method creates or checks a queue
        channel.queue_declare(queue=self.queueName)

        # Binds the queue to the specified exchange
        channel.queue_bind(queue=self.queueName,
                        exchange=self.config['exchange'],
                        routing_key=self.bindingKey)

        channel.basic_consume(queue=self.queueName,
                            on_message_callback=self.on_message_callback,
                            auto_ack=False)

        print('[*] Waiting for data for ' + self.queueName + '. To exit press CTRL+C')

        try:

            channel.start_consuming()

        except KeyboardInterrupt:

            channel.stop_consuming()


queueName = 'secap'
key = 'mspl.create'
notification_consumer_config = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : 'tasks',
                                'login':'tubs',
                                'password':'sbut'}

if __name__ == '__main__':

    try:

       init_rabbit = RMQsubscriber(queueName, key, notification_consumer_config)
       init_rabbit.setup()

    except KeyboardInterrupt:

        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)