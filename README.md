# ada2025

<img src="https://i.postimg.cc/Hp8vxZR6/localhost-5000-machines-1.png">

Desktop machines in the cloud prototype

## Setup

### Web app setup

```
git clone https://github.com/dvolk/ada2
cd ada2
python3 -m venv env
source env/bin/activate
pip3 install flask flask-sqlalchemy flask-migrate flask-login docker humanize argh
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
