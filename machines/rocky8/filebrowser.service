[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
User=ubuntu
Environment="USER=ubuntu"
WorkingDirectory=/home/ubuntu
ExecStart=/usr/local/bin/filebrowser --baseurl=/browse --noauth -r /home/ubuntu
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
