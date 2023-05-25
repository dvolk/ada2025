#!/bin/sh

# Check if the INIT_DB variable is set
if [ "$INIT_DB" = "true" ]
then
    flask db init
fi

# Check if the MIGRATE_DB variable is set
if [ "$MIGRATE_DB" = "true" ]
then
    flask db migrate
fi

flask db upgrade

exec python3 app.py "$@"
