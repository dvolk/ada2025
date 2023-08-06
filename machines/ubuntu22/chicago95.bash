# Download theme and background
cd ~
mkdir -p ~/.themes
mkdir -p ~/.icons
wget https://github.com/grassmunk/Chicago95/archive/5670fde8ce33b33d37622b888278aa9cdbe5eea2.zip
unzip 5670fde8ce33b33d37622b888278aa9cdbe5eea2.zip
cd Chicago95-5670fde8ce33b33d37622b888278aa9cdbe5eea2
cp -r Theme/Chicago95 ~/.themes
cp -r Icons/* ~/.icons
cd ..
wget http://www.dvd3000.ca/wp/content/win95/png/Clouds.png
rm -rf 5670fde8ce33b33d37622b888278aa9cdbe5eea2.zip
rm -rf Chicago95-5670fde8ce33b33d37622b888278aa9cdbe5eea2
xfconf-query -c xsettings -p /Net/ThemeName -s 'Chicago95'
xfconf-query -c xfwm4 -p /general/theme -s 'Chicago95'
xfconf-query -c xsettings -p /Net/IconThemeName -s 'Chicago95'
