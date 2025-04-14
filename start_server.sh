#!/bin/bash
echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Running migrations..."
python manage.py migrate

echo "Starting Django development server on port ${PORT:-8000}..."
python manage.py runserver 0.0.0.0:${PORT:-8000}
