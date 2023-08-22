#!/bin/bash

set -x
set -e

# Set environment variables
export DEBIAN_FRONTEND=noninteractive
export VNC_PORT=5900
export NOVNC_PORT=6080
export VNC_PW=vncpassword
export USER=ubuntu
export FILEBROWSER_DL=https://github.com/filebrowser/filebrowser/releases/download/v2.23.0/linux-amd64-filebrowser.tar.gz

# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------

# Update packages and install required packages
dnf install -y epel-release
dnf update -y
dnf --enablerepo=epel group
dnf groupinstall -y "Xfce" "base-x"



dnf install -y tar xorg-x11-fonts-Type1 \
    tigervnc-server tigervnc tigervnc-server-minimal nginx \
    nginx-mod-stream unzip xfce4-screenshooter
pip3 install --upgrade --ignore-installed pip setuptools
pip3 install websockify



# Download and install filebrowser
curl -fsSL $FILEBROWSER_DL -o filebrowser.tar.gz
tar -xzf filebrowser.tar.gz
mv filebrowser /usr/local/bin
chmod +x /usr/local/bin/filebrowser
rm -f filebrowser.tar.gz



# Install some more useful utilities - can we get screenfetch in here, it doesn't seem to be on any of the repos?
dnf install -y wget git vim-enhanced nano\
    tmux htop ncdu tree bc zip unzip \
    rsync



# Install novnc
git clone --branch add_clipboard_support https://github.com/juanjoDiaz/noVNC.git /usr/share/novnc
cd /usr/share/novnc
git checkout 24dbf21474ca88928c5a7d63b39fc950240591f7
cd -



# Install desktop applications
dnf install -y emacs firefox



# Install theming and fonts
dnf install -y gnome-themes-standard tango-icon-theme mate-themes dejavu-sans-fonts



# Setup desktop user 'ubuntu'
#echo "$USER:$USER" | chpasswd
echo "$USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USER
chmod 0440 /etc/sudoers.d/$USER
useradd -m -s /bin/bash ubuntu
usermod -aG audio,video,cdrom,adm,dialout,wheel $USER



# Allow the user to save screenshots to web server
mkdir -p /var/www/html/screenshots
chown -R $USER:$USER /var/www/html/screenshots



# Copy the nginx config file
mv /etc/nginx/conf.d/ /etc/nginx/sites-enabled/
cp nginx-ada.conf /etc/nginx/sites-enabled/nginx-ada.conf
# Copy nginx front page
cp index.html /var/www/html/index.html
cp ada.png /var/www/html/ada.png



# cronjob: take a screenshot every minute
crontab -u $USER -l | { cat; echo '* * * * * xfce4-screenshooter -f -o /var/www/html/screenshots/screenshot.png'; } | crontab -u $USER -



# copy systemd unit files
cp filebrowser.service /etc/systemd/system
cp websockify.service /etc/systemd/system
cp vncserver.service /etc/systemd/system



# copy nginx config
cp -f nginx.conf /etc/nginx



# reload systemd
systemctl daemon-reload



# copy certs
mkdir -p /etc/nginx/keys/
cp secrets/nubes.stfc.ac.uk-combined.crt /etc/nginx/keys/
cp secrets/nubes.stfc.ac.uk.key /etc/nginx/keys/



# enable xfce, disable gnome
sudo dnf remove -y gnome-shell gnome-session gnome-control-center



# Set up VNC
mkdir -p /home/$USER/.vnc
echo $VNC_PW | vncpasswd -f > /home/$USER/.vnc/passwd
chown -R $USER:$USER /home/$USER/.vnc
chmod 600 /home/$USER/.vnc/passwd
dnf remove -y xfce4-power-manager



# don't boot into X by default since it's started by vncserver
sudo systemctl set-default multi-user.target



# enable ada services
systemctl enable vncserver.service filebrowser.service websockify.service nginx.service
systemctl start vncserver.service filebrowser.service websockify.service nginx.service



# copy .ssh folder to ubuntu
cp -r /root/.ssh/ /home/ubuntu/.ssh/
chown -R ubuntu:ubuntu /home/ubuntu/.ssh/



# configure xfce4
su ubuntu << EOF
export DISPLAY=:0
xfconf-query -c xsettings -p /Net/ThemeName -s 'Adwaita'
xfconf-query -c xfwm4 -p /general/theme -s "Adwaita" --create --type string
xfconf-query -c xsettings -p /Net/IconThemeName -s 'Tango'
xfconf-query -c xfce4-session -p /general/LockCommand -s "false"
xfconf-query -c xfce4-panel -p /panels/dark-mode -s false --create --type bool
EOF
