# Use the official Python base image
FROM python:3.11-slim

# Set the working directory to /app
WORKDIR /app

# Install build-essential and other dependencies for psycopg2 (PostgreSQL client)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    pkg-config \
&& rm -rf /var/lib/apt/lists/*


RUN apt-get update && apt-get install -y \
    libgobject-2.0-0 \
    libglib2.0-0 \
    libgirepository-1.0-1 \
    gir1.2-glib-2.0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# FOR THE LDAPs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libldap2-dev \
    libsasl2-dev \
    slapd \
    ldap-utils \
    tox \
    lcov \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt into the container
COPY requirements.txt /app/

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Copy the entire project into the container
COPY . /app/

EXPOSE 8000

CMD ["./start_server.sh"]
