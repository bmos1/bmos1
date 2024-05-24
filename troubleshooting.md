# Change IP
* https://devconnected.com/how-to-change-ip-address-on-linux/
* 

```bash
sudo ifconfig eth0 192.168.178.32/24
nmcli device modify eth0 ipv4.address 192.168.178.32/24
nmcli device reapply eth0
```

# For recovering a deleted image use the following command
/home/offsec/
* https://www.geeksforgeeks.org/how-to-recover-a-deleted-file-in-linux/
* -t file extension
* -o output dir
* -i file
* -q block size 512

```bash
sudo apt install foremost
sudo foremost -v -t png -i /dev/sda1 -o ~/test
sudo foremost -v -t jpg -i /dev/sda3 -o ~/test
```
