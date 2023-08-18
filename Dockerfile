FROM python:3.10.12-alpine3.18

WORKDIR /usr/app

ADD galle.py .

RUN pip install proxy-protocol

CMD [ "python", "/usr/app/galle.py", "/usr/app/config.ini" ]
