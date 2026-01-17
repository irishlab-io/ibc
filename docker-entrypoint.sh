#!/bin/sh
set -e

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --noinput

# Execute the main command
exec "$@"
