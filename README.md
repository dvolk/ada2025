# ada2025

Desktop machines in the cloud

<img src="https://i.postimg.cc/w98KvNxz/localhost-5000-machines-3.png">

## Features

- Docker container with full Debian XFCE desktop
- Create machines from machine templates
- Share machines with other users
- Open desktop in a web browser
- Upload and download files with integrated file browser

## Setup

### Web app setup

```
git clone https://github.com/dvolk/ada2
cd ada2
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

Build docker desktop container:

```
docker build . -f Dockerfile.ws -t workspace
```

### Run web app

```
python3 app.py
```

open http://localhost:5000
