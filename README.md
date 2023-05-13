# ada2025

Flask web app for desktop machines in the cloud

<table>
<thead>
<th width=50%>Machine page</th>
<th width=50%>Data page</th>
</thead>
<tr>
<td>
<img src="https://i.postimg.cc/v88QT879/localhost-5000-machines-18.png">
</td>
<td>
<img src="https://i.postimg.cc/38F830GY/localhost-5000-data-3.png">
</td>
</tr>
</table>

## Features

- Create machines from machine templates
- Run machines as:
  - docker containers
  - libvirt virtual machines
  - openstack virtual machines, all in one unified interface
- Share machines with other users
- Copy data from data sources into machines
- Open desktop in a web browser
- Upload and download files with integrated file browser
- Internationalization: en, zh, sl
- Login with a local account or Google, with optional reCaptcha

## Tech used

- Python 3.11+
- Flask
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-WTForms
- Flask-Login
- Flask-Admin
- Flask-Babel
- Flask-Limiter
- Flask-ReCaptcha
- Authlib
- Debian
- Docker
- libvirt
- python-openstack
- TigerVNC
- noVNC
- filebrowser
- nginx
- rsync

## Installation and running

### Web app setup

```
git clone https://github.com/dvolk/ada2025
cd ada2025
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
pybabel compile -d translations
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

### libvirt setup

1. Install a new debian 11 system on a virtual machine named "debian11-5"
2. Copy the files in machines/debian11_vm to the virtual machine
3. ssh into the virtual machine and run setup.bash
4. Shut down the virtual machine

### Optional config

You can set the following optional environment variables:

```
ADA2025_SQLALCHEMY_URL=(set to database url if you don't want sqlite)
LOGIN_RECAPTCHA=(set to 1 if you want recaptcha on login screen)
RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=
GOOGLE_OAUTH2_CLIENT_ID=
GOOGLE_OAUTH2_CLIENT_SECRET=
```

### Run web app

```
python3 app.py
```

open http://localhost:5000

## How-to

### Updating translation .po files

```
pybabel -v extract  -F babel.cfg -o translations/messages.pot .
pybabel update -N -i translations/messages.pot -d translations
```
