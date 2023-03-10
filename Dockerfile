FROM python:3.9.6
ENV PYTHONUNBUFFERED 1
ADD requirements.txt /app/
WORKDIR /app
RUN apt-get update && apt-get upgrade --yes
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
