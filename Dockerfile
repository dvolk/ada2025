# Use the official Python 3.11 image as the base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Install various requirements
RUN apt update && \
    apt -y install --no-install-recommends \
    build-essential \
    libvirt-clients \
    virtinst \
    libvirt-dev \
    python3-openstackclient \
    python3-glanceclient \
    libpq-dev

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

# copy and define entrypoint
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
