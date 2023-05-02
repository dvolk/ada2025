# Set the base image to Ubuntu 20.04
FROM ubuntu:22.04

# Install necessary packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    xfce4 xfce4-goodies tightvncserver python3 python3-pip nginx git

# Install some apps
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    chromium-browser emacs xterm 

# Install noVNC
RUN pip3 install numpy && \
    git clone https://github.com/novnc/noVNC.git /opt/noVNC && \
    ln -s /opt/noVNC/vnc_lite.html /opt/noVNC/index.html

# Configure Nginx to proxy to noVNC
RUN rm /etc/nginx/sites-enabled/default && \
    echo "upstream vnc_server { server 127.0.0.1:5901; }" > /etc/nginx/conf.d/upstream.conf && \
    echo "server { listen 80; location / { proxy_pass http://vnc_server; } }" > /etc/nginx/sites-enabled/default

# Set up the VNC server
RUN useradd -ms /bin/bash ubuntu && \
    usermod -a -G sudo,adm,dip,plugdev ubuntu && \
    su - ubuntu -c "mkdir -p /home/ubuntu/.vnc" && \
    echo "password" | su - ubuntu -c "vncpasswd -f > /home/ubuntu/.vnc/passwd" && \
    su - ubuntu -c "chmod 0600 /home/ubuntu/.vnc/passwd" && \
    su - ubuntu -c "touch /home/ubuntu/.Xresources" && \
    echo "xrdb /home/ubuntu/.Xresources" >> /home/ubuntu/.bashrc && \
    echo "startxfce4 &" >> /home/ubuntu/.vnc/xstartup && \
    chmod +x /home/ubuntu/.vnc/xstartup && \
    chown -R ubuntu:ubuntu /home/ubuntu && \
    sed -i 's/\/root/\/home\/ubuntu/g' /etc/passwd

# Expose the Nginx HTTP port
EXPOSE 5901

# Start Nginx and the VNC server
CMD nginx && \
    su - ubuntu -c "vncserver :1 -geometry 1280x800 -depth 24" && \
    tail -f /home/ubuntu/.vnc/*.log
