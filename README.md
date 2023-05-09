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
<table>
<thead>
<th width=50%>Machine menu</th>
<th width=50%>Share page</th>
</thead>
<tr>
<td>
<img src="https://i.postimg.cc/fzNW4fJ8/10-10-10-2.png">
</td>
<td>
<img src="https://i.postimg.cc/gGx230CH/localhost-5000-share-machine-2.png ">
</td>
</tr>
</table>

## Features

- Create machines from machine templates
- Run machines as docker containers and libvirt virtual machines
- Share machines with other users
- Copy data from data sources into machines
- Open desktop in a web browser
- Upload and download files with integrated file browser

## Tech used

- Python 3.11+
- Flask
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-WTForms
- Flask-Login
- Flask-Admin
- nginx
- Docker
- libvirt
- TigerVNC
- noVNC
- filebrowser
- rsync

## Setup

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
