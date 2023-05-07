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
apt-get -y install firefox-esr webext-ublock-origin-firefox emacs

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
apt purge -y xfce4-power-manager
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
crontab -l -u $USER | { cat; echo '* * * * * DISPLAY=:0 scrot -t 20 -o /var/www/html/screenshots/screenshot.png'; } | crontab -u $USER -

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
