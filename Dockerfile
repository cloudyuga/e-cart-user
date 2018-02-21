FROM python:latest
COPY . /usr/src/app
WORKDIR /usr/src/app
RUN pip install virtualenv
RUN virtualenv flask
RUN flask/bin/pip install -r requirements.txt
CMD flask/bin/python user.py
