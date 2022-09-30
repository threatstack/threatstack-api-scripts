
#  GetVulnerabilities
This Python3 script is used to get all vulnerabilities for rules from an organization and write them to CSV. Each vulnerabilities is done on a per host basis. This is a very long running script due to the amount of data that is pulled for small tenets the file that is produced can quickly hit 300 MB.

```
cveNumber,reportedPackage,systemPackage,vectorType,severity,isSuppressed,securityNotices,agents,agentId,id,kernelId,instanceType,privateDnsName,privateIpAddress,groups,subnetId,keyName,region,launchTime,imageId,architecture,publicDnsName,publicIpAddress,vpcId,awsProfile,monitored,tags,state,stateCode

```

## Usage: Return all vulnerabilites
---

```bash
python3 get_get_vulnerabilities.py
```

## Usage: Return only vulnerabilites with active notices
---

```bash
python3 get_get_vulnerabilities.py --notices
```


## Usage: Return all active vulnerabilites from an alternate organization
---

```bash
python3 get_get_vulnerabilities.py --org STAGING
```

## Setting up the configuration file
---
The configuration file is divided into at least two sections:  
`[USER_INFO]` contains your user's credentials, which are the same across organizations.  
`[DEFAULT]` contains the organization ID for the organization you wish to default to, as well as a name to use for the CSV files the script generates.  
If you wish to add multiple organizations to the file, create additional sections (for example, `[STAGING]` or `[UA]`) and then reference them with the `--org` argument from the main script.
```
[USER_INFO]
# TS_USER_ID - User ID of the API key holder
# The key is user specific, not organization specific.
TS_USER_ID = a1b2c3d4
# TS_API_KEY - API key for the user specified by TS_USER_ID
TS_API_KEY = 9z8y7x6w

[DEFAULT]
# TS_ORGANIZATION_ID - Organization ID of the organization to access
TS_ORGANIZATION_ID = 0123456
# TS_ORGANIZATION_NAME - Organization Name to use in output filenames
TS_ORGANIZATION_NAME = "Production"

[STAGING]
# TS_ORGANIZATION_ID - Organization ID of the organization to access
TS_ORGANIZATION_ID = 6543210
# TS_ORGANIZATION_NAME - Organization Name to use in output filenames
TS_ORGANIZATION_NAME = "Staging"
```