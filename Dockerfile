FROM python:3.10

RUN apt-get update && apt-get install -y ffmpeg

RUN mkdir /app
WORKDIR /app

ADD requirements.txt ./

RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple && \
pip config set install.trusted-host mirrors.aliyun.com && \
pip install -r requirements.txt

ADD *.py ./

CMD ["python","main.py"]