[Unit]
Description=Websockify
After=network.target

[Service]
Type=simple
User=ubuntu
Environment="VNC_PORT=5901"
ExecStart=/usr/bin/websockify --web /usr/share/novnc/ 5901 localhost:5900
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
