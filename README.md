# ada2025

Flask web app to manage cloud-based desktop machines

<p align="center">
  <img src="https://i.postimg.cc/v88QT879/localhost-5000-machines-18.png" width="45%" alt="Machine Page"/>
  <img src="https://i.postimg.cc/38F830GY/localhost-5000-data-3.png" width="45%" alt="Data Page"/>
</p>

# Overview

Ada2025 allows you to create, run, and share machines from various templates, all through a single, unified interface. This interface can also be used to manipulate data sources, use a desktop in a web browser, manage files through an integrated file browser, and much more.

# Key Features
- Create machines from pre-defined templates
- Manage machines across various platforms:
  - Docker containers
  - Libvirt virtual machines
  - OpenStack virtual machines
- Share machine access with other users
- Import data from various sources into your machines
- Access a fully-featured desktop environment in your browser
- Integrated file browser for uploading and downloading files
- Multi-language support: English, Chinese, Slovenian
- Login with local account or Google, with optional reCaptcha for added security
- In-app user problem reporting system
- Colorful admin interface with action auditing for increased transparency
- Easy deployment options with bare metal or Docker

# Tech Stack

The following technologies were used to build Ada2025:

- Backend: Python 3.11+, Flask, Flask-SQLAlchemy, Flask-Migrate, Flask-WTForms, Flask-Login, Flask-Admin, Flask-Babel, Flask-Limiter, Flask-ReCaptcha, Authlib
- Infrastructure: Debian, Docker, libvirt, python-openstack
- Frontend: TigerVNC, noVNC, filebrowser
- Networking: Nginx
- Data Transfer: rsync

# Installation and Setup

Follow these steps to get Ada2025 running on your machine:

## Web app setup

Clone the repository and install the required Python packages:


```
git clone https://github.com/dvolk/ada2025
cd ada2025
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
pybabel compile -d translations
```

## Database setup

Initialize and set up the database:

```
flask db init
flask db migrate
flask db upgrade
```

## Docker setup

Create a Docker bridge network and build the example Docker desktop container:

```
docker network create --driver bridge --subnet=10.10.10.0/24 --gateway=10.10.10.1 adanet
cd machines/docker_example
docker build . -f Dockerfile -t workspace
```

## libvirt setup

Follow these steps to prepare a libvirt virtual machine:

1. Install a new Debian 11 system on a virtual machine named "debian11-5".
2. Copy the files located in machines/debian11_vm to the virtual machine.
3. SSH into the virtual machine and execute setup.bash.
4. Shut down the virtual machine.

## Optional Configuration

You can also set the following optional environment variables to further configure Ada2025:

```
ADA2025_FLASK_SECRET_KEY  # set to string or one will be randomly generated
ADA2025_SQLALCHEMY_URL  # set to database URL if you don't want SQLite
LOGIN_RECAPTCHA  # set to 1 if you want reCaptcha on the login screen
RECAPTCHA_SITE_KEY  # your reCaptcha v2 site key
RECAPTCHA_SECRET_KEY  # your reCaptcha secret key
GOOGLE_OAUTH2_CLIENT_ID  # your Google OAuth2 client ID
GOOGLE_OAUTH2_CLIENT_SECRET  # your Google OAuth2 client secret
```

## Running the Web App

To run the web app:

```
python3 app.py
```

Then, open your web browser and navigate to http://localhost:5000.

## Additional Guides

### Updating translation .po files

To update the translation files, use the following commands:

```
pybabel -v extract  -F babel.cfg -o translations/messages.pot .
pybabel update -N -i translations/messages.pot -d translations
```

For further assistance, please open an issue or reach out directly.
