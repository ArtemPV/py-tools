FROM python:3.9.7 

RUN pip install kubernetes pyOpenSSL prometheus-client prometheus_client \
    && mkdir -p /root/.kube /app

COPY config /root/.kube/config
COPY main.py /app/main.py 

WORKDIR /app

CMD [ "/usr/local/bin/python", "/app/main.py" ]