#!/bin/sh
flask db init
flask db migrate
flask db upgrade
exec python3 app.py "$@"
