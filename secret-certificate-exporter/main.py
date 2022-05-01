#!/usr/bin/env python3

import base64
import time
from datetime import datetime
from OpenSSL import crypto
from kubernetes import client, config
from prometheus_client.core import GaugeMetricFamily, REGISTRY
from prometheus_client import start_http_server

class CustomCollector(object):
    def __init__(self):
        pass

    def collect(self):
        config.load_kube_config()
        cv1 = client.CoreV1Api()
        secret_list = cv1.list_secret_for_all_namespaces(watch=False)

        g = GaugeMetricFamily("secret_certificate_expire_time_seconds", 'Not After', labels=['namespace', 'secret'])
        for i in secret_list.items:
            for n in i.data:
                cert_list = i.data[n]
                try:
                    cert_list_bytes = cert_list.encode('ascii')
                    base64_clb = base64.b64decode(cert_list_bytes)
                    base64_message = base64_clb.decode('ascii')
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, base64_message)
                    convert_cert = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    time_stamp = datetime.timestamp(convert_cert)
                    g.add_metric([i.metadata.namespace, i.metadata.name], time_stamp)
                except:
                    None
                
        yield g

if __name__ == '__main__':
    start_http_server(8000)
    REGISTRY.register(CustomCollector())
    while True:
        time.sleep(1)






