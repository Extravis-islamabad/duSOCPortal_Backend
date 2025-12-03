#!/bin/bash

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Running migrations..."
python manage.py migrate

echo "Collecting the Static files"
python manage.py collectstatic --noinput

echo "Starting Django app with Uvicorn on port ${PORT:-8000}..."
uvicorn sockportal__backend.asgi:application --host 0.0.0.0 --port ${PORT:-8000} --workers 1
