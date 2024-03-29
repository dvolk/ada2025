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

echo "Running apt update..."
apt update

echo "Checking current Ubuntu version..."

if [ "$(cat /etc/issue | head -c 12)" != "Ubuntu 22.04" ]; then

    if [ -n "$(apt list --upgradable 2>/dev/null | grep -v Listing)" ]; then
        echo "Upgradable packages found. Running apt upgrade in 10 seconds..."
        sleep 10
        apt upgrade -o Dpkg::Options::='--force-confold' --force-yes -fuy -y

        echo "System will reboot in 10 seconds..."
        sleep 10
        exit 0
    else
        echo "No upgradable packages found."
    fi
fi

if [ "$(cat /etc/issue | head -c 12)" != "Ubuntu 22.04" ]; then
    echo "Starting Ubuntu upgrade in 10 seconds..."
    sleep 10
    export DEBIAN_FRONTEND=noninteractive
    echo 'Dpkg::Options {
"--force-confdef";
"--force-confold";
}'>/etc/apt/apt.conf.d/local

    yes N | do-release-upgrade -m server -f DistUpgradeViewNonInteractive

    echo "System will reboot in 10 seconds..."
    sleep 10
    exit 0
fi

# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------

# Update packages and install required packages
apt-get update
apt-get install -y dbus-x11 xfce4 xfce4-goodies xfonts-base xfonts-100dpi \
    xfonts-75dpi xfonts-scalable tigervnc-standalone-server tigervnc-common \
    tigervnc-xorg-extension websockify nginx nginx-extras sudo curl \
    unzip scrot cron


# Download and install filebrowser
curl -fsSL $FILEBROWSER_DL -o filebrowser.tar.gz
tar -xzf filebrowser.tar.gz
mv filebrowser /usr/local/bin
chmod +x /usr/local/bin/filebrowser
rm -f filebrowser.tar.gz



# Install some more useful utilities
apt-get install -y coreutils findutils grep sed gawk gzip tar curl wget git openssl \
        vim nano tmux htop ncdu tree file less bc zip unzip ssh rsync procps screenfetch s3cmd \
        rclone rclone-browser


# Install novnc
git clone --branch add_clipboard_support https://github.com/juanjoDiaz/noVNC.git /usr/share/novnc
cd /usr/share/novnc
git checkout 24dbf21474ca88928c5a7d63b39fc950240591f7
cd -


# Install desktop applications and themes
apt-get -y install emacs materia-gtk-theme abiword gnumeric pinta


# Setup desktop user 'ubuntu'
#echo "$USER:$USER" | chpasswd
#echo "$USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USER
#chmod 0440 /etc/sudoers.d/$USER
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

if [ "$BUILD_NGINX_TLS_KEYS" = "nubes.stfc.ac.uk" ]; then
    cp secrets/nubes.stfc.ac.uk-combined.crt /etc/nginx/keys
    cp secrets/nubes.stfc.ac.uk.key /etc/nginx/keys
fi

if [ "$BUILD_NGINX_TLS_KEYS" = "machine.ada.oxfordfun.com" ]; then
    cp secrets/machine.ada.oxfordfun.com.fullchain.cer /etc/nginx/keys
    cp secrets/machine.ada.oxfordfun.com.key /etc/nginx/keys

    sed -i 's|nubes.stfc.ac.uk-combined.crt|machine.ada.oxfordfun.com.fullchain.cer|' /etc/nginx/sites-enabled/nginx-ada.conf
    sed -i 's|nubes.stfc.ac.uk.key|machine.ada.oxfordfun.com.key|' /etc/nginx/sites-enabled/nginx-ada.conf
fi

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

# create user datasets directory
su ubuntu <<EOF
mkdir -p /home/ubuntu/datasets
EOF

# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------

# OPTIONAL: Add /media/ada-user-share (stfc cloud only)
if [ "$BUILD_INSTALL_ADA_USER_SHARE" = "True" ]; then
    # set up ada-user-share
    apt install -y sshfs
    mkdir /media/ada-user-share
    chown ubuntu:ubuntu /media/ada-user-share
    cp ada-user-share.service /etc/systemd/system
    systemctl daemon-reload
    systemctl enable ada-user-share
fi

# OPTIONAL: Install build-essential, gnuplot, cmake, libscalapack
if [ "$BUILD_INSTALL_BUILD_ENV" = "True" ]; then
    apt install -y build-essential gnuplot cmake gfortran libscalapack-openmpi-dev libopenmpi-dev openmpi-bin libarpack2-dev libarpack++2-dev pyqt5-dev zlib1g-dev
fi

# OPTIONAL: Install ollama
if [ "$BUILD_INSTALL_BUILD_OLLAMA" = "True" ]; then
    curl https://ollama.ai/install.sh | sh
fi

# OPTIONAL: Install Ada 2025 Software Installer
if [ "$BUILD_INSTALL_ADA2025_SOFTWARE_INSTALLER" = "True" ]; then
    apt install -y python3-pip python3-venv
    su ubuntu<<EOF
git clone https://github.com/oxfordfun/ada2025-software-installer.git /home/ubuntu/ada2025-software-installer
python3 -m venv /home/ubuntu/ada2025-software-installer/env
/home/ubuntu/ada2025-software-installer/env/bin/pip3 install -r /home/ubuntu/ada2025-software-installer/requirements.txt

cp /home/ubuntu/ada2025-software-installer/ada2025-software-installer.desktop /home/ubuntu/Desktop/
chown ubuntu /home/ubuntu/Desktop/ada2025-software-installer.desktop
chmod +x /home/ubuntu/Desktop/ada2025-software-installer.desktop
EOF
fi

# OPTIONAL: Install libreoffice
if [ "$BUILD_INSTALL_LIBREOFFICE" = "True" ]; then
    sudo apt -y install libreoffice
fi

# OPTIONAL: Install the gimp image manipulation tool
if [ "$BUILD_INSTALL_GIMP" = "True" ]; then
    sudo apt -y install gimp
fi

# OPTIONAL: install R and Rstudio server
if [ "$BUILD_INSTALL_RSTUDIO" = "True" ]; then
    apt install -y r-base
    # TODO host this file locally
    wget -q https://download2.rstudio.org/server/jammy/amd64/rstudio-server-2023.06.0-421-amd64.deb
    set +e
    dpkg -i rstudio-server-2023.06.0-421-amd64.deb
    apt install -y -f
    set -e
    rm rstudio-server-2023.06.0-421-amd64.deb
    cp rstudio-server.service /usr/lib/systemd/system/rstudio-server.service
    systemctl daemon-reload
    systemctl restart rstudio-server.service
fi

# OPTIONAL: Install Python and jupyter lab+notebook
if [ "$BUILD_INSTALL_JUPYTER" = "True" ]; then
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
fi

# OPTIONAL: Install CUDA, tensorflow and tensorboard
if [ "$BUILD_INSTALL_CUDA_ETC" = "True" ]; then
    wget -q https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-ubuntu2204.pin
    mv cuda-ubuntu2204.pin /etc/apt/preferences.d/cuda-repository-pin-600 # what does this do?

    # cuda 11.8 (and nvidia driver 520)
    wget -q https://developer.download.nvidia.com/compute/cuda/11.8.0/local_installers/cuda-repo-ubuntu2204-11-8-local_11.8.0-520.61.05-1_amd64.deb
    dpkg -i cuda-repo-ubuntu2204-11-8-local_11.8.0-520.61.05-1_amd64.deb
    sudo cp /var/cuda-repo-ubuntu2204-11-8-local/cuda-D95DBBE2-keyring.gpg /usr/share/keyrings/
    apt update
    apt install -y cuda
    rm cuda-repo-ubuntu2204-11-8-local_11.8.0-520.61.05-1_amd64.deb

    # cudnn 8.6.0
    wget -q https://developer.download.nvidia.com/compute/redist/cudnn/v8.6.0/local_installers/11.8/cudnn-local-repo-ubuntu2204-8.6.0.163_1.0-1_amd64.deb
    dpkg -i cudnn-local-repo-ubuntu2204-8.6.0.163_1.0-1_amd64.deb
    sudo cp /var/cudnn-local-repo-ubuntu2204-8.6.0.163/cudnn-local-FAED14DD-keyring.gpg /usr/share/keyrings/
    apt update
    apt install -y libcudnn8 libcudnn8-dev libcudnn8-samples
    rm cudnn-local-repo-ubuntu2204-8.6.0.163_1.0-1_amd64.deb

    # tensorrt 8.6.1 for cuda 11.8
    wget -q https://developer.nvidia.com/downloads/compute/machine-learning/tensorrt/secure/8.6.1/local_repos/nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8_1.0-1_amd64.deb
    dpkg -i nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8_1.0-1_amd64.deb
    sudo cp /var/nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8/nv-tensorrt-local-0628887B-keyring.gpg /usr/share/keyrings/
    apt update
    apt install -y tensorrt tensorrt-dev
    rm nv-tensorrt-local-repo-ubuntu2204-8.6.1-cuda-11.8_1.0-1_amd64.deb
fi

# OPTIONAL: Install tensorflow and tensorboard
if [ "$BUILD_INSTALL_TENSORFLOW_TENSORBOARD" = "True" ]; then
    su ubuntu << EOF
/home/ubuntu/jupyter-env/bin/pip3 install tensorflow tensorboard
echo "export CUDA_DIR=/usr/lib/cuda/" >> /home/ubuntu/.bashrc
/home/ubuntu/jupyter-env/bin/pip3 install scikit-learn scipy pandas pandas-datareader matplotlib pillow tqdm requests h5py pyyaml flask boto3 bayesian-optimization gym kaggle
EOF
    cp tensorboard.service /etc/systemd/system/tensorboard.service
    systemctl daemon-reload
    systemctl enable tensorboard.service
    systemctl start tensorboard.service
fi

# OPTIONAL: Install docker
if [ "$BUILD_INSTALL_DOCKER" = "True" ]; then
    apt install -y docker.io
    usermod -a -G docker ubuntu
fi

# OPTIONAL: Install apptainer
if [ "$BUILD_INSTALL_APPTAINER" = "True" ]; then
    wget -q https://github.com/apptainer/apptainer/releases/download/v1.1.9/apptainer_1.1.9_amd64.deb
    wget -q https://github.com/apptainer/apptainer/releases/download/v1.1.9/apptainer-suid_1.1.9_amd64.deb

    set +e
    dpkg -i apptainer_1.1.9_amd64.deb
    apt install -y -f
    dpkg -i apptainer-suid_1.1.9_amd64.deb
    set -e

    rm apptainer_1.1.9_amd64.deb
    rm apptainer-suid_1.1.9_amd64.deb
fi

# OPTIONAL: Install emacs-gotty service
if [ "$BUILD_INSTALL_EMACS_GOTTY"  = "True" ]; then
    # Add emacs config emacs config file and the tmux conf for better colors
    su ubuntu <<EOF
mkdir /home/ubuntu/.emacs.d
cp init.el /home/ubuntu/.emacs.d/init.el
cp .tmux.conf /home/ubuntu/.tmux.conf
EOF
    chown ubuntu:ubuntu /home/ubuntu/.emacs.d/init.el

    wget -q https://github.com/yudai/gotty/releases/download/v1.0.1/gotty_linux_amd64.tar.gz
    tar xf gotty_linux_amd64.tar.gz
    mv gotty /usr/bin
    rm gotty_linux_amd64.tar.gz
    cp emacs-gotty.service /etc/systemd/system/emacs-gotty.service
    systemctl daemon-reload
    systemctl enable emacs-gotty.service
    systemctl start emacs-gotty.service
fi

# OPTIONAL: Install code-server
if [ "$BUILD_INSTALL_CODE_SERVER" = "True" ]; then
    curl -fsSL https://code-server.dev/install.sh | sh
    # modified service file disables authentication and telemetry
    cp code-server@.service /lib/systemd/system/code-server@.service
    systemctl daemon-reload
    systemctl enable code-server@ubuntu.service
    systemctl restart code-server@ubuntu.service
fi


# OPTIONAL: Install miniconda3
if [ "$BUILD_INSTALL_MINICONDA3" = "True" ]; then
    su ubuntu <<EOF
wget -q https://repo.anaconda.com/miniconda/Miniconda3-py310_23.3.1-0-Linux-x86_64.sh
bash ./Miniconda3-py310_23.3.1-0-Linux-x86_64.sh -b
/home/ubuntu/miniconda3/bin/conda init
# /home/ubuntu/miniconda3/bin/conda config --set auto_activate_base false?
rm ./Miniconda3-py310_23.3.1-0-Linux-x86_64.sh
EOF
fi

# OPTIONAL: Install spyder (same env as jupyter)
if [ "$BUILD_INSTALL_SPYDER" = "True" ]; then
    su ubuntu << EOF
/home/ubuntu/jupyter-env/bin/pip3 install spyder==5.4.3
wget -q https://raw.githubusercontent.com/spyder-ide/spyder/master/img_src/spyder.png
cp spyder.png /home/ubuntu/Downloads/spyder.png
cp spyder.desktop /home/ubuntu/Desktop/spyder.desktop
chmod a+x /home/ubuntu/Desktop/spyder.desktop
EOF
fi

# OPTIONAL: Install the nix package manager
if [ "$BUILD_INSTALL_NIX" = "True" ]; then
    wget -q https://nixos.org/nix/install
    chmod a+x install
    yes | ./install --daemon
fi

# OPTIONAL: Install paraview
if [ "$BUILD_INSTALL_PARAVIEW" = "True" ]; then
    wget 'https://www.paraview.org/paraview-downloads/download.php?submit=Download&version=v5.11&type=binary&os=Linux&downloadFile=ParaView-5.11.1-MPI-Linux-Python3.9-x86_64.tar.gz' -O ParaView-5.11.1-MPI-Linux-Python3.9-x86_64.tar.gz
    tar xf ParaView-5.11.1-MPI-Linux-Python3.9-x86_64.tar.gz -C /opt

    su ubuntu << EOF
cp paraview.desktop /home/ubuntu/Desktop
chmod a+x /home/ubuntu/Desktop/paraview.desktop
EOF
fi

# OPTIONAL: Install CCP-EM v1
if [ "$BUILD_INSTALL_CCP_EM_v1" = "True" ]; then
    wget https://www.ccpem.ac.uk/downloads/ccpem_distributions/ccpem-20221108-linux-x86_64.tar.gz
    tar xf ccpem-20221108-linux-x86_64.tar.gz -C /opt
    touch /root/.agree2ccpemv1
    ./opt/ccpem-20221108-linux-x86_64/install_ccpem.sh

    su ubuntu << EOF
cp CCP-EM.desktop /home/ubuntu/Desktop
chmod a+x /home/ubuntu/Desktop/CCP-EM.desktop
EOF
fi

# OPTIONAL: Install CCP-EM doppio
if [ "$BUILD_INSTALL_DOPPIO" = "True" ]; then
    wget https://www.ccpem.ac.uk/downloads/doppio/doppio-linux-beta4-2023-09-08.zip
    mkdir /opt/doppio
    unzip doppio-linux-beta4-2023-09-08.zip -d /opt/doppio

    su ubuntu<<EOF
cp Doppio.desktop /home/ubuntu/Desktop
chmod a+x /home/ubuntu/Desktop/Doppio.desktop
EOF
fi

# OPTIONAL: Install Icy
if [ "$BUILD_INSTALL_ICY" = "True" ]; then
    wget -q https://ada-files.oxfordfun.com/software/Icy/Icy-2.4.3.tar.gz
    tar -xf Icy-2.4.3.tar.gz -C /
    rm Icy-2.4.3.tar.gz
    apt install -y default-jre
    chmod +x /home/ubuntu/Desktop/Icy.desktop
fi

# OPTIONAL: Install Ilastik
if [ "$BUILD_INSTALL_ILASTIK" = "True" ]; then
    wget -q https://ada-files.oxfordfun.com/software/Ilastik/Ilasktik-1.4.0.tar.gz
    tar -xf Ilasktik-1.4.0.tar.gz -C /
    rm Ilasktik-1.4.0.tar.gz
    chmod +x /home/ubuntu/Desktop/Ilastik.desktop
fi

# OPTIONAL: Install ImageJ
if [ "$BUILD_INSTALL_IMAGEJ" = "True" ]; then
    wget -q https://ada-files.oxfordfun.com/software/ImageJ/ImageJ-1.53.tar.gz
    tar -xf ImageJ-1.53.tar.gz -C /
    rm -f ImageJ-1.53.tar.gz
    chmod +x /home/ubuntu/Desktop/ImageJ2.desktop
fi

# OPTIONAL: Install MIB
if [ "$BUILD_INSTALL_MIB" = "True" ]; then
    wget -q https://ada-files.oxfordfun.com/software/MIB/MIB-2.48.tar.gz
    tar -xf MIB-2.48.tar.gz -C /
    rm -f MIB-2.48.tar.gz
    chmod +x /home/ubuntu/Desktop/MIB.desktop
fi

# OPTIONAL: Install NAPARI
if [ "$BUILD_INSTALL_NAPARI" = "True" ]; then
    wget -q https://ada-files.oxfordfun.com/software/Napari/Napari-0.4.17.tar.gz
    tar -xf Napari-0.4.17.tar.gz -C /
    rm -f Napari-0.4.17.tar.gz
    apt install -y libqt5core5a:amd64 libqt5gui5:amd64
    chmod +x /home/ubuntu/Desktop/Napari.desktop
    su ubuntu << EOF
/home/ubuntu/napari-env/bin/pip install okapi-em napari-ome-zarr
EOF
fi

# OPTIONAL: Download RFI example datasets
if [ "$BUILD_INSTALL_RFI_EXAMPLE_DATASETS" = "True" ]; then
    su ubuntu << EOF
mkdir -p /home/ubuntu/datasets
mkdir -p /home/ubuntu/datasets/CLEM-Reg-tutorial
wget -q --content-disposition 'https://zenodo.org/record/7936982/files/EM04468_2_63x_pos8T_LM_raw.tif?download=1' -O /home/ubuntu/datasets/CLEM-Reg-tutorial/EM04468_2_63x_pos8T_LM_raw.tif
wget -q --content-disposition 'https://zenodo.org/record/7936982/files/em_20nm_z_40_145.tif?download=1' -O /home/ubuntu/datasets/CLEM-Reg-tutorial/em_20nm_z_40_145.tif
EOF
fi


# OPTIONAL: Install Aspera. REQUIRES conda above
if [ "$BUILD_INSTALL_ASPERA" = "True" ]; then
    # install aspera-cli
    su ubuntu << EOF
/home/ubuntu/miniconda3/bin/conda install -c hcc aspera-cli -y
EOF

    # install aspera connect
    wget -q https://d3gcli72yxqn2z.cloudfront.net/downloads/connect/latest/bin/ibm-aspera-connect_4.2.7.445_linux_x86_64.tar.gz
    tar xzf ibm-aspera-connect_4.2.7.445_linux_x86_64.tar.gz
    su ubuntu <<EOF
bash ibm-aspera-connect_4.2.7.445_linux_x86_64.sh
EOF

    # install aspera connect firefox extension
    wget -q https://addons.mozilla.org/firefox/downloads/file/3909084/ibm_aspera_connect-4.1.1.1.xpi
    mkdir -p /usr/local/share/ibm_aspera_connect-4.1.1.1_xpi
    unzip ibm_aspera_connect-4.1.1.1.xpi -d /usr/local/share/ibm_aspera_connect-4.1.1.1_xpi
    echo "/usr/local/share/ibm_aspera_connect-4.1.1.1_xpi" > /usr/lib/firefox-addons/extensions/connect@aspera.ibm.com
fi

# OPTIONAL: Install Aspera. REQUIRES conda above
if [ "$BUILD_INSTALL_GLOBUS" = "True" ]; then
    su ubuntu << EOF
/home/ubuntu/miniconda3/bin/conda install -c conda-forge globus-cli -y
EOF
fi

if [ "$BUILD_GROUP_FLAVOR" = "sciml" ]; then
    # - Change the theme to Adwaita
    # - Change the icons to Tango
    # - Turn off xfce panel dark mode
    # - Set the background to the stfc sciml image

    # xfconf-query requires DBUS_SESSION_BUS_ADDRESS
    pid=$(pgrep -u ubuntu xfce4-session)
    dbus_address=$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/$pid/environ | cut -d= -f2-)

    su ubuntu << EOF
export DISPLAY=:0
export DBUS_SESSION_BUS_ADDRESS="$dbus_address"
xfconf-query -c xsettings -p /Net/ThemeName -s 'Adwaita'
xfconf-query -c xfwm4 -p /general/theme -s 'Adwaita'
xfconf-query -c xsettings -p /Net/IconThemeName -s 'Tango'
xfconf-query -c xfce4-panel -p /panels/dark-mode -s false
wget -q https://www.scd.stfc.ac.uk/Gallery/pixabay_artificial-intelligence-3382521_1920.jpg -O /home/ubuntu/.sciml_bg.jpg
xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitorVNC-0/workspace0/last-image -s /home/ubuntu/.sciml_bg.jpg
EOF
fi

if [ "$BUILD_GROUP_FLAVOR" = "rfi" ]; then
    # - Change the theme to Adwaita
    # - Change the icons to Tango
    # - Turn off xfce panel dark mode
    # - Set the background to the stfc sciml image

    # xfconf-query requires DBUS_SESSION_BUS_ADDRESS
    pid=$(pgrep -u ubuntu xfce4-session)
    dbus_address=$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/$pid/environ | cut -d= -f2-)

    su ubuntu << EOF
export DISPLAY=:0
export DBUS_SESSION_BUS_ADDRESS="$dbus_address"
xfconf-query -c xsettings -p /Net/ThemeName -s 'Adwaita'
xfconf-query -c xfwm4 -p /general/theme -s 'Adwaita'
xfconf-query -c xsettings -p /Net/IconThemeName -s 'Tango'
xfconf-query -c xfce4-panel -p /panels/dark-mode -s false
wget -q https://ada-files.oxfordfun.com/software/misc/vEMlogo_purwhitecell.jpg -O /home/ubuntu/.rfi_bg.jpg
xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitorVNC-0/workspace0/last-image -s /home/ubuntu/.rfi_bg.jpg
wget -q --content-disposition https://ada-files.oxfordfun.com/software/misc/README.pdf -O /home/ubuntu/Desktop/README.pdf
EOF
fi

if [ "$BUILD_GROUP_FLAVOR" = "generic" ]; then
    # - Change the theme to Adwaita
    # - Change the icons to Tango
    # - Turn off xfce panel dark mode
    # - Set the background to the stfc sciml image

    # xfconf-query requires DBUS_SESSION_BUS_ADDRESS
    pid=$(pgrep -u ubuntu xfce4-session)
    dbus_address=$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/$pid/environ | cut -d= -f2-)

    su ubuntu << EOF
export DISPLAY=:0
export DBUS_SESSION_BUS_ADDRESS="$dbus_address"
xfconf-query -c xsettings -p /Net/ThemeName -s 'Adwaita'
xfconf-query -c xfwm4 -p /general/theme -s 'Adwaita'
xfconf-query -c xsettings -p /Net/IconThemeName -s 'Tango'
xfconf-query -c xfce4-panel -p /panels/dark-mode -s false
wget -q 'https://i.postimg.cc/0xKPfwRD/ada-bg-normal.png?dl=1' -O /home/ubuntu/.ada-bg-normal.png
xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitorVNC-0/workspace0/last-image -s /home/ubuntu/.ada-bg-normal.png
EOF
fi

if [ "$BUILD_GROUP_FLAVOR" = "generic-training" ]; then
    # - Change the theme to Adwaita
    # - Change the icons to Tango
    # - Turn off xfce panel dark mode
    # - Set the background to the stfc sciml image

    # xfconf-query requires DBUS_SESSION_BUS_ADDRESS
    pid=$(pgrep -u ubuntu xfce4-session)
    dbus_address=$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/$pid/environ | cut -d= -f2-)

    su ubuntu << EOF
export DISPLAY=:0
export DBUS_SESSION_BUS_ADDRESS="$dbus_address"
xfconf-query -c xsettings -p /Net/ThemeName -s 'Adwaita'
xfconf-query -c xfwm4 -p /general/theme -s 'Adwaita'
xfconf-query -c xsettings -p /Net/IconThemeName -s 'Tango'
xfconf-query -c xfce4-panel -p /panels/dark-mode -s false
wget -q 'https://i.postimg.cc/Mqkxrpq4/ada-bg-training.png?dl=1' -O /home/ubuntu/.ada-bg-training.png
xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitorVNC-0/workspace0/last-image -s /home/ubuntu/.ada-bg-training.png
EOF
fi



# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------

echo "System will reboot in 10 seconds..."
sleep 10
exit 0
