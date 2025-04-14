# Use the official Python base image
FROM python:3.10-slim

# Set the working directory to /app
WORKDIR /app

# Install build-essential and other dependencies for psycopg2 (PostgreSQL client)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    pkg-config \
&& rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt into the container
COPY requirements.txt /app/

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Copy the entire project into the container
COPY . /app/

EXPOSE 8000

CMD ["./start_server.sh"]
