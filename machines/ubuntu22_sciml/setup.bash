#!/bin/bash

# Set environment variables
export DEBIAN_FRONTEND=noninteractive
export VNC_PORT=5900
export NOVNC_PORT=6080
export VNC_PW=vncpassword
export USER=ubuntu
export FILEBROWSER_DL=https://github.com/filebrowser/filebrowser/releases/download/v2.23.0/linux-amd64-filebrowser.tar.gz

# Update packages and install required packages
apt-get update
apt-get install -y dbus-x11 xfce4 xfce4-goodies xfonts-base xfonts-100dpi \
    xfonts-75dpi xfonts-scalable tigervnc-standalone-server tigervnc-common \
    tigervnc-xorg-extension novnc websockify nginx nginx-extras sudo curl \
    unzip scrot cron



# Download and install filebrowser
curl -fsSL $FILEBROWSER_DL -o filebrowser.tar.gz
tar -xzf filebrowser.tar.gz
mv filebrowser /usr/local/bin
chmod +x /usr/local/bin/filebrowser
rm -f filebrowser.tar.gz



# Install some more useful utilities
apt-get install -y coreutils findutils grep sed gawk gzip tar curl wget git openssl \
    vim nano tmux htop ncdu tree file less bc zip unzip ssh rsync procps screenfetch



# Install desktop applications
apt-get -y install emacs materia-gtk-theme



# Add desktop user 'ubuntu'
useradd -m -s /bin/bash $USER
echo "$USER:$USER" | chpasswd
echo "$USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USER
chmod 0440 /etc/sudoers.d/$USER
usermod -aG audio,video,cdrom,plugdev,staff,adm,dialout,sudo $USER



# Set up VNC
mkdir -p /home/$USER/.vnc
echo $VNC_PW | vncpasswd -f > /home/$USER/.vnc/passwd
chown -R $USER:$USER /home/$USER/.vnc
chmod 600 /home/$USER/.vnc/passwd
apt purge -y xfce4-power-manager xfce4-screensaver
rm /etc/nginx/sites-enabled/default



# Allow the user to save screenshots to web server
mkdir /var/www/html/screenshots
chown -R $USER:$USER /var/www/html/screenshots



# Copy the nginx config file
cp nginx-ada.conf /etc/nginx/sites-enabled/nginx-ada.conf
# Copy nginx front page
cp index.html /var/www/html/index.html
cp ada.png /var/www/html/ada.png



# cronjob: take a screenshot every minute
crontab -l -u $USER | { cat; echo '* * * * * DISPLAY=:0 scrot -z -t 20 -o /var/www/html/screenshots/screenshot.png'; } | crontab -u $USER -



# don't boot into X by default since it's started by vncserver
sudo systemctl set-default multi-user.target



# copy systemd unit files
cp filebrowser.service /etc/systemd/system
cp websockify.service /etc/systemd/system
cp vncserver.service /etc/systemd/system



# reload systemd
systemctl daemon-reload



# enable ada services
systemctl enable vncserver.service filebrowser.service websockify.service
systemctl start vncserver.service filebrowser.service websockify.service


# copy certs
mkdir -p /etc/nginx/keys
cp nubes.stfc.ac.uk-combined.crt /etc/nginx/keys
cp nubes.stfc.ac.uk.key /etc/nginx/keys


# remove snap firefox and install deb version

# snap firefox doesn't seem to work with the way the desktop
# is started with vncserver. This seems to be a common
# problem with no obvious solution, but it might be solved
# in future ubuntu releases
snap remove firefox

add-apt-repository -y ppa:mozillateam/ppa

echo '
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001
' | tee /etc/apt/preferences.d/mozilla-firefox

echo 'Unattended-Upgrade::Allowed-Origins:: "LP-PPA-mozillateam:${distro_codename}";' | tee /etc/apt/apt.conf.d/51unattended-upgrades-firefox

apt install -y firefox webext-ublock-origin-firefox



# OPTIONAL: install R and Rstudio server
apt install -y r-base
# TODO host this file locally
wget https://download2.rstudio.org/server/jammy/amd64/rstudio-server-2023.06.0-421-amd64.deb
dpkg -i rstudio-server-2023.06.0-421-amd64.deb
apt install -y -f
rm rstudio-server-2023.06.0-421-amd64.deb
cp rstudio-server.service /usr/lib/systemd/system/rstudio-server.service
systemctl daemon-reload
systemctl restart rstudio-server.service


# OPTIONAL: Install Python and jupyter notebook
apt install -y python3-pip python3-venv

su ubuntu << EOF
python3 -m venv /home/ubuntu/jupyter-env
/home/ubuntu/jupyter-env/bin/pip3 install notebook
mkdir -p /home/ubuntu/.jupyter
mkdir -p /home/ubuntu/notebooks
cp jupyter_notebook_config.py /home/ubuntu/.jupyter/jupyter_notebook_config.py
EOF

cp jupyter.service /etc/systemd/system
systemctl daemon-reload
systemctl enable jupyter.service
systemctl start jupyter.service
systemctl restart nginx


# OPTIONAL: Install CUDA, tensorflow and tensorboard

# agree to nvidia licence
echo "nvidia-cudnn nvidia-cudnn/license select true" | sudo debconf-set-selections
echo "nvidia-cudnn nvidia-cudnn/question select I Agree" | sudo debconf-set-selections

apt install -y nvidia-driver-530 nvidia-utils-530 nvidia-cuda-toolkit nvidia-cuda-toolkit-gcc nvidia-cudnn

su ubuntu << EOF
/home/ubuntu/jupyter-env/bin/pip3 install tensorflow tensorboard
echo "export CUDA_DIR=/usr/lib/cuda/" >> /home/ubuntu/.bashrc
EOF

cp tensorboard.service /etc/systemd/system/tensorboard.service
systemctl daemon-reload
systemctl enable tensorboard.service
systemctl start tensorboard.service


# OPTIONAL: Install docker
apt install -y docker.io
usermod -a -G docker ubuntu


# OPTIONAL: Install apptainer

wget https://github.com/apptainer/apptainer/releases/download/v1.1.9/apptainer_1.1.9_amd64.deb
wget https://github.com/apptainer/apptainer/releases/download/v1.1.9/apptainer-suid_1.1.9_amd64.deb

dpkg -i apptainer_1.1.9_amd64.deb
apt install -y -f
dpkg -i apptainer-suid_1.1.9_amd64.deb

rm apptainer_1.1.9_amd64.deb
rm apptainer-suid_1.1.9_amd64.deb


### THE END
