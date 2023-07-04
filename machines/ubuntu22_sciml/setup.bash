#!/bin/bash

echo "Running apt update..."
apt update

echo "Checking current Ubuntu version..."

if [ "$(cat /etc/issue | head -c 12)" != "Ubuntu 22.04" ]; then

    if [ -n "$(apt list --upgradable 2>/dev/null | grep -v Listing)" ]; then
        echo "Upgradable packages found. Running apt upgrade in 10 seconds..."
        sleep 10
        apt upgrade -y

        echo "System will reboot in 10 seconds..."
        sleep 10
        reboot
    else
        echo "No upgradable packages found."
    fi
fi

if [ "$(cat /etc/issue | head -c 12)" != "Ubuntu 22.04" ]; then
    echo "Starting Ubuntu upgrade in 10 seconds..."
    sleep 10
    export DEBIAN_FRONTEND=noninteractive
    yes N | do-release-upgrade -f DistUpgradeViewNonInteractive

    echo "System will reboot in 10 seconds..."
    sleep 10
    reboot
fi


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


# stuff below is optional


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


# OPTIONAL: Install Python and jupyter lab+notebook
apt install -y python3-pip python3-venv

su ubuntu << EOF
python3 -m venv /home/ubuntu/jupyter-env
/home/ubuntu/jupyter-env/bin/pip3 install notebook
mkdir -p /home/ubuntu/.jupyter-notebook
cp jupyter_notebook_config.py /home/ubuntu/.jupyter-notebook/jupyter_notebook_config.py

/home/ubuntu/jupyter-env/bin/pip3 install jupyterlab
mkdir -p /home/ubuntu/.jupyter-lab
cp jupyter_lab_config.py /home/ubuntu/.jupyter-lab/jupyter_lab_config.py

mkdir -p /home/ubuntu/notebooks
EOF

cp jupyter-notebook.service /etc/systemd/system
cp jupyter-lab.service /etc/systemd/system
systemctl daemon-reload
systemctl enable jupyter-notebook.service jupyter-lab.service
systemctl start jupyter-notebook.service jupyter-lab.service
systemctl restart nginx


# OPTIONAL: Install CUDA, tensorflow and tensorboard

wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-ubuntu2204.pin
mv cuda-ubuntu2204.pin /etc/apt/preferences.d/cuda-repository-pin-600 # what does this do?

# cuda 11.8 (and nvidia driver 520)
wget https://developer.download.nvidia.com/compute/cuda/11.8.0/local_installers/cuda-repo-ubuntu2204-11-8-local_11.8.0-520.61.05-1_amd64.deb
dpkg -i cuda-repo-ubuntu2204-11-8-local_11.8.0-520.61.05-1_amd64.deb
sudo cp /var/cuda-repo-ubuntu2204-11-8-local/cuda-D95DBBE2-keyring.gpg /usr/share/keyrings/
apt update
apt install -y cuda
rm cuda-repo-ubuntu2204-11-8-local_11.8.0-520.61.05-1_amd64.deb

# cudnn 8.6.0
wget https://developer.download.nvidia.com/compute/redist/cudnn/v8.6.0/local_installers/11.8/cudnn-local-repo-ubuntu2204-8.6.0.163_1.0-1_amd64.deb
dpkg -i cudnn-local-repo-ubuntu2204-8.6.0.163_1.0-1_amd64.deb
sudo cp /var/cudnn-local-repo-ubuntu2204-8.6.0.163/cudnn-local-FAED14DD-keyring.gpg /usr/share/keyrings/
apt update
apt install -y libcudnn8 libcudnn8-dev libcudnn8-samples
rm cudnn-local-repo-ubuntu2204-8.6.0.163_1.0-1_amd64.deb

# tensorrt 8.6.1 for cuda 11.8
wget https://developer.nvidia.com/downloads/compute/machine-learning/tensorrt/secure/8.6.1/local_repos/nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8_1.0-1_amd64.deb
dpkg -i nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8_1.0-1_amd64.deb
sudo cp /var/nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8/nv-tensorrt-local-0628887B-keyring.gpg /usr/share/keyrings/
apt update
apt install -y tensorrt tensorrt-dev
rm nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8_1.0-1_amd64.deb

su ubuntu << EOF
/home/ubuntu/jupyter-env/bin/pip3 install tensorflow tensorboard
echo "export CUDA_DIR=/usr/lib/cuda/" >> /home/ubuntu/.bashrc
/home/ubuntu/jupyter-env/bin/pip3 install scikit-learn scipy pandas pandas-datareader matplotlib pillow tqdm requests h5py pyyaml flask boto3 bayesian-optimization gym kaggle
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


# OPTIONAL: Install emacs-gotty service

# Add emacs config emacs config file and the tmux conf for better colors
su ubuntu <<EOF
mkdir /home/ubuntu/.emacs.d
cp init.el /home/ubuntu/.emacs.d/init.el
cp .tmux.conf /home/ubuntu/.tmux.conf
EOF
chown ubuntu:ubuntu /home/ubuntu/.emacs.d/init.el

wget https://github.com/yudai/gotty/releases/download/v1.0.1/gotty_linux_amd64.tar.gz
tar xf gotty_linux_amd64.tar.gz
mv gotty /usr/bin
rm gotty_linux_amd64.tar.gz
cp emacs-gotty.service /etc/systemd/system/emacs-gotty.service
systemctl daemon-reload
systemctl enable emacs-gotty.service
systemctl start emacs-gotty.service


# OPTIONAL: Install code-server


curl -fsSL https://code-server.dev/install.sh | sh
# modified service file disables authentication and telemetry
cp code-server@.service /lib/systemd/system/code-server@.service
systemctl daemon-reload
systemctl enable code-server@ubuntu.service
systemctl restart code-server@ubuntu.service



# OPTIONAL: Install miniconda3


su ubuntu <<EOF
wget https://repo.anaconda.com/miniconda/Miniconda3-py310_23.3.1-0-Linux-x86_64.sh
bash ./Miniconda3-py310_23.3.1-0-Linux-x86_64.sh -b
/home/ubuntu/miniconda3/bin/conda init
# /home/ubuntu/miniconda3/bin/conda config --set auto_activate_base false?
rm ./Miniconda3-py310_23.3.1-0-Linux-x86_64.sh
EOF


# OPTIONAL: Install spyder


su ubuntu << EOF
/home/ubuntu/jupyter-env/bin/pip3 install spyder==5.4.3
wget https://raw.githubusercontent.com/spyder-ide/spyder/master/img_src/spyder.png
cp spyder.png /home/ubuntu/Downloads/spyder.png
cp spyder.desktop /home/ubuntu/Desktop/spyder.desktop
chmod a+x /home/ubuntu/Desktop/spyder.desktop
EOF


### THE END
