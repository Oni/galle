FROM python:python:3.8.17-alpine3.18

ADD gallant.py /usr/app

RUN pip install proxy-protocol

WORKDIR /usr/app

CMD [ "python", "/usr/app/gallant.py", "/usr/app/gallant.py" ]
