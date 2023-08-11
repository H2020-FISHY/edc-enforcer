FROM eclipse-temurin:17-jre-jammy
WORKDIR $HOME/srv

#Python installation
RUN apt update && apt install -y
RUN apt install python3-pip -y
RUN apt install python3-venv -y

#Create venv within the container
RUN python3 -m venv /srv/venv

#Activate venv and install requirements
COPY requirements.txt .
RUN . /srv/venv/bin/activate && pip install -r requirements.txt

COPY . .

EXPOSE 5000

#Activate venv and run flask
CMD . /srv/venv/bin/activate && python3 ./enforcer.py
