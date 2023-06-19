[Unit]
Description=VNC Server
After=network.target

[Service]
Type=simple
User=ubuntu
ExecStart=/usr/bin/vncserver :0 -geometry 1280x800 -SecurityTypes=None -fg
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
