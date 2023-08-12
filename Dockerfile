FROM python:python:3.8.17-alpine3.18

ADD galle.py /usr/app

RUN pip install proxy-protocol

WORKDIR /usr/app

CMD [ "python", "/usr/app/galle.py", "/usr/app/config.ini" ]
