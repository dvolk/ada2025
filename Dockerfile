# Use the official Python 3.11 image as the base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Install libvirt requirements
RUN apt update && \
    apt -y install --no-install-recommends \
        build-essential virtinst libvirt-dev

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Copy the rest of the application's source code into the container
COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Define the command to run the app
CMD flask db init && \
    flask db migrate && \
    flask db upgrade && \
    python3 app.py
