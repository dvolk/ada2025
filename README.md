# ada2025

Flask web app for desktop machines in the cloud

<img src="https://i.postimg.cc/Nsx40Jj5/localhost-5000-machines-12.png"> <img src="https://i.postimg.cc/GLRKdwrW/10-10-10-4.png">


## Features

- Create machines from machine templates
- Share machines with other users
- Open desktop in a web browser
- Upload and download files with integrated file browser
- Example docker container with Debian 11 XFCE desktop

## Tech used

- Python 3.11+
- Flask
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-WTForms
- Flask-Login
- nginx
- Docker
- TigerVNC
- noVNC
- filebrowser

## Setup

### Web app setup

```
git clone https://github.com/dvolk/ada2025
cd ada2025
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
```

### Set up database

```
flask db init
flask db migrate
flask db upgrade
```

### Docker setup

Create docker bridge network:

```
docker network create --driver bridge --subnet=10.10.10.0/24 --gateway=10.10.10.1 adanet
```

Build example docker desktop container:

```
cd machines/docker_example
docker build . -f Dockerfile -t workspace
```

### Run web app

```
python3 app.py
```

open http://localhost:5000
