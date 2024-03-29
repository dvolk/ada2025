#!/bin/bash

set -x
set -e

sleep 360

# Set environment variables
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
dnf groupinstall -y "Xfce" "base-x" --exclude gdm --exclude plymouth*



dnf install -y tar xorg-x11-fonts-Type1 \
    tigervnc-server tigervnc tigervnc-server-minimal nginx \
    nginx-mod-stream unzip xfce4-screenshooter ImageMagick redhat-lsb
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



# take a screenshot every minute
cp screenshot.service screenshot.timer /etc/systemd/system
systemctl daemon-reload
systemctl enable screenshot.timer
systemctl start screenshot.timer



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



# Set up VNC
mkdir -p /home/$USER/.vnc
echo $VNC_PW | vncpasswd -f > /home/$USER/.vnc/passwd
chown -R $USER:$USER /home/$USER/.vnc
chmod 600 /home/$USER/.vnc/passwd
dnf remove -y xfce4-power-manager xfce4-screensaver



# don't boot into X by default since it's started by vncserver
sudo systemctl set-default multi-user.target



# remove polkit
rm -f /etc/xdg/autostart/xfce-polkit.desktop



# enable ada services
systemctl enable vncserver.service filebrowser.service websockify.service nginx.service
systemctl start vncserver.service filebrowser.service websockify.service nginx.service


# wait for desktop to come up?
sleep 10


# set up ssh keys
mkdir -p /home/ubuntu/.ssh
chown -R ubuntu:ubuntu /home/ubuntu/.ssh/
wget https://github.com/dvolk.keys -O /home/ubuntu/.ssh/authorized_keys



# configure xfce4
pid=$(pgrep -u ubuntu xfce4-session)
dbus_address=$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/$pid/environ | cut -d= -f2-)

su ubuntu << EOF
export DISPLAY=:0
export DBUS_SESSION_BUS_ADDRESS="$dbus_address"

xfconf-query -c xsettings -p /Net/ThemeName -s 'Adwaita'
xfconf-query -c xfwm4 -p /general/theme -s 'Adwaita' --create --type string
xfconf-query -c xsettings -p /Net/IconThemeName -s 'Tango'
xfconf-query -c xfce4-panel -p /panels/dark-mode -s false
xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/lock-screen -s false --create --type bool

wget -q http://www.dvd3000.ca/wp/content/win95/png/Clouds.png -O /home/ubuntu/.Clouds.png
xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitorVNC-0/workspace0/last-image -s /home/ubuntu/.Clouds.png
EOF
