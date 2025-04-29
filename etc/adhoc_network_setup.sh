# 1. Stop the wireless service
sudo systemctl stop wpa_supplicant.service
sudo killall wpa_supplicant
sudo systemctl stop NetworkManager 

# 2. Configure the wireless interface
# Create a new configuration file for the ad hoc network
sudo tee /etc/network/interfaces.d/adhoc.conf << EOF
auto wlan0
iface wlan0 inet static
    address 192.168.1.X  # Replace X with unique number for each Pi (1,2,3,etc)
    netmask 255.255.255.0
    wireless-channel 36
    wireless-essid MyAdHocNetwork
    wireless-mode ad-hoc
EOF

# 3. Set up routing if needed
# Enable IP forwarding
sudo tee /etc/sysctl.d/99-adhoc.conf << EOF
net.ipv4.ip_forward=1
EOF

# Apply sysctl settings
sudo sysctl -p /etc/sysctl.d/99-adhoc.conf

# 4. Configure wireless parameters
sudo iwconfig wlan0 mode ad-hoc
sudo iwconfig wlan0 essid "MyAdHocNetwork"
sudo iwconfig wlan0 channel 36

# 5. Bring up the interface with new settings
sudo ifconfig wlan0 down
sudo ifconfig wlan0 192.168.1.X netmask 255.255.255.0 up  # Replace X with Pi number

# 6. Optional: Add static routes if needed
# Example: Route traffic to another Pi
sudo ip route add 192.168.1.0/24 via 192.168.1.1 dev wlan0

# 7. Test connectivity
# On each Pi, try pinging the others:
# ping 192.168.1.1  # or whatever IP you assigned to other Pis
