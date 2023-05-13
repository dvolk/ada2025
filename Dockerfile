# Use the official Python 3.11 image as the base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Install various requirements
RUN apt update && \
    apt -y install --no-install-recommends \
    build-essential \
    libvirt-clients virtinst libvirt-dev \ # libvirt support
    python3-openstackclient \ # openstack support
    libpq-dev # sqlalchemy postgres support

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Copy the rest of the application's source code into the container
COPY . .

# Compile translations
RUN pybabel compile -d translations

# Expose the port the app runs on
EXPOSE 5000

# Define the command to run the app
CMD flask db init && \
    flask db migrate && \
    flask db upgrade && \
    python3 app.py
