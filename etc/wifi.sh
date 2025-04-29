#!/bin/bash
# This script disables ad hoc networking and restores normal WiFi connectivity

echo "Stopping ad hoc network configuration..."
sudo ifconfig wlan0 down
sudo systemctl start wpa_supplicant.service

sudo rm /etc/network/interfaces

echo "Stopping DHCP service if running..."

echo "Restoring normal WiFi configuration..."
sudo wpa_cli reconfigure

sudo systemctl enable NetworkManager
sudo systemctl start NetworkManager

echo "Restarting networking service..."
sudo systemctl restart networking

echo "Bringing wireless interface back up..."
sudo ifconfig wlan0 up

echo "Network configuration reset completed."
echo "If WiFi doesn't connect automatically, you may need to reboot with: sudo reboot"
