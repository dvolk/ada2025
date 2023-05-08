FROM debian:bullseye

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
        novnc \
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

# Install desktop applications
RUN apt-get -y install firefox-esr webext-ublock-origin-firefox emacs

# Add desktop user 'ubuntu'
RUN useradd -m -s /bin/bash $USER && \
    echo "$USER:$USER" | chpasswd && \
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

RUN chown $USER:$USER /home/$USER/.ssh/authorized_keys && \

# Set up VNC
RUN mkdir -p /home/$USER/.vnc && \
    echo $VNC_PW | vncpasswd -f > /home/$USER/.vnc/passwd && \
    chown -R $USER:$USER /home/$USER/.vnc && \
    chmod 600 /home/$USER/.vnc/passwd && \
    apt purge -y xfce4-power-manager && \
    rm  /etc/nginx/sites-enabled/default

# allow the user to save screenshots to web server
RUN mkdir /var/www/html/screenshots && \
    chown -R $USER:$USER /var/www/html/screenshots

EXPOSE $NOVNC_PORT
WORKDIR /home/$USER

# Start nginx, vncserver, filebrowser and websockify
CMD service nginx start & \
    service cron start && \
    service ssh start && \
    su -c "vncserver :0 -geometry 1280x800 -SecurityTypes=None && \
    filebrowser --baseurl=/browse --noauth -r /home/$USER & \
    sleep 1 && \
    crontab -l -u $USER | { cat; echo '* * * * * DISPLAY=:0 scrot -t 20 -o /var/www/html/screenshots/screenshot.png'; } | crontab -u $USER - && \
    websockify --web /usr/share/novnc/ 5901 localhost:$VNC_PORT && \
    tail -F /home/$USER/.vnc/*:0.log" $USER
