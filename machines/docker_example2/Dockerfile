FROM ubuntu:23.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    VNC_PORT=5900 \
    NOVNC_PORT=6080 \
    VNC_PW=vncpassword \
    USER=ubuntu \
    FILEBROWSER_DL=https://github.com/filebrowser/filebrowser/releases/download/v2.23.0/linux-amd64-filebrowser.tar.gz

# Install required packages
RUN apt-get update && \
    apt-get install -y \
        dbus-x11 \
        xfce4 \
        xfce4-goodies \
        xfonts-base \
        xfonts-100dpi \
        xfonts-75dpi \
        xfonts-scalable \
        tigervnc-standalone-server \
        tigervnc-common \
        tigervnc-xorg-extension \
        websockify \
        nginx \
        nginx-extras \
        sudo \
        curl \
        unzip \
        scrot \
        cron

# Download and install filebrowser
RUN curl -fsSL $FILEBROWSER_DL -o filebrowser.tar.gz && \
    tar -xzf filebrowser.tar.gz && \
    mv filebrowser /usr/local/bin && \
    chmod +x /usr/local/bin/filebrowser && \
    rm -f filebrowser.tar.gz

# Install some more useful utilities
RUN sudo apt-get install -y \
        coreutils findutils grep sed gawk gzip tar curl wget git openssl \
        vim nano tmux htop ncdu tree file less bc zip unzip \
        ssh rsync procps screenfetch

# Install novnc with clipboard api support
RUN git clone --branch add_clipboard_support https://github.com/juanjoDiaz/noVNC.git /usr/share/novnc && \
    cd /usr/share/novnc && \
    git checkout 24dbf21474ca88928c5a7d63b39fc950240591f7

RUN openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=US/ST=California/L=San Francisco/O=YourCompany/OU=Org/CN=www.yourdomain.com" && \
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt && \
    mkdir /etc/nginx/ssl && \
    cp server.key server.crt /etc/nginx/ssl

# Install desktop applications
RUN apt-get -y install emacs xterm materia-gtk-theme

# Add desktop user 'ubuntu'
RUN echo "$USER:$USER" | chpasswd && \
    echo "$USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USER && \
    chmod 0440 /etc/sudoers.d/$USER && \
    mkdir /home/$USER/.ssh && \
    chmod 755 /home/$USER/.ssh && \
    chown $USER:$USER /home/$USER/.ssh && \
    usermod -aG audio,video,cdrom,plugdev,staff,adm,dialout,sudo $USER

# Copy the nginx config file
COPY nginx-ada.conf /etc/nginx/sites-enabled/nginx-ada.conf
# Copy nginx front page
COPY index.html /var/www/html/index.html
COPY ada.png /var/www/html/ada.png
COPY dvolk.keys /home/ubuntu/.ssh/authorized_keys

# install .deb firefox
RUN apt install -y software-properties-common && \
    add-apt-repository -y ppa:mozillateam/ppa && \
    echo "Package: * \nPin: release o=LP-PPA-mozillateam \nPin-Priority: 1001" | tee /etc/apt/preferences.d/mozilla-firefox && \
    echo "Unattended-Upgrade::Allowed-Origins:: \"LP-PPA-mozillateam:${distro_codename}\";" | tee /etc/apt/apt.conf.d/51unattended-upgrades-firefox && \
    apt install -y firefox webext-ublock-origin-firefox

RUN chown $USER:$USER /home/$USER/.ssh/authorized_keys

# Set up VNC
RUN mkdir -p /home/$USER/.vnc && \
    echo $VNC_PW | vncpasswd -f > /home/$USER/.vnc/passwd && \
    chown -R $USER:$USER /home/$USER/.vnc && \
    chmod 600 /home/$USER/.vnc/passwd && \
    apt purge -y xfce4-power-manager gnome-terminal && \
    rm  /etc/nginx/sites-enabled/default

# allow the user to save screenshots to web server
RUN mkdir /var/www/html/screenshots && \
    chown -R $USER:$USER /var/www/html/screenshots

EXPOSE $NOVNC_PORT
WORKDIR /home/$USER

# Download theme and background
RUN su ubuntu -c "cd ~ && \
    mkdir -p ~/.themes && \
    mkdir -p ~/.icons && \
    wget https://github.com/grassmunk/Chicago95/archive/5670fde8ce33b33d37622b888278aa9cdbe5eea2.zip && \
    unzip 5670fde8ce33b33d37622b888278aa9cdbe5eea2.zip && \
    cd Chicago95-5670fde8ce33b33d37622b888278aa9cdbe5eea2 && \
    cp -r Theme/Chicago95 ~/.themes && \
    cp -r Icons/* ~/.icons && \
    cd .. && \
    wget http://www.dvd3000.ca/wp/content/win95/png/Clouds.png && \
    rm -rf 5670fde8ce33b33d37622b888278aa9cdbe5eea2.zip && \
    rm -rf Chicago95-5670fde8ce33b33d37622b888278aa9cdbe5eea2 && \
    echo \"xfconf-query -c xsettings -p /Net/ThemeName -s 'Chicago95'\" >> ~/set-theme.sh && \
    echo \"xfconf-query -c xfwm4 -p /general/theme -s 'Chicago95'\" >> ~/set-theme.sh && \
    echo \"xfconf-query -c xsettings -p /Net/IconThemeName -s 'Chicago95'\" >> ~/set-theme.sh"

# Start nginx, vncserver, filebrowser and websockify
CMD service nginx start & \
    service cron start && \
    service ssh start && \
    su -c "vncserver :0 -geometry 1280x800 -SecurityTypes=None -xstartup startxfce4 && \
    filebrowser --baseurl=/browse --noauth -r /home/$USER & \
    sleep 1 && \
    crontab -l -u $USER | { cat; echo '* * * * * DISPLAY=:0 scrot -z -t 20 -o /var/www/html/screenshots/screenshot.png'; } | crontab -u $USER - && \
    websockify --timeout 86400 --idle-timeout 86400 --web /usr/share/novnc/ 5901 localhost:$VNC_PORT && \
    tail -F /home/$USER/.vnc/*:0.log" $USER
