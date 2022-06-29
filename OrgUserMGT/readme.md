
#  Organization Management
There are mulitple scripts that can be used to manage the users in a clients Organization. The reason for spliting these into the three scripts is to allow for less arguments to have to be passed to run the needed action. 

Actions are 
+ Invite a new user
+ Add or Remove a user from an Organization
+ Create a CSV file of all users in an Organization

##  invite_user.py
This Python3 script is used to invite users to your Organization. The script expects the role to be either a "user", "reader" as well as the user's email address. 

### Usage: Creates a new user in the Threat Stack platform
---


```bash
python3 invite_user.py --config threatstack.cfg --user-role <"user", "reader"> --user-email <users email>
```

### Usage: Creates a new user in the Threat Stack platform multiple orgs in config
---

```bash
python3 invite_user.py --config threatstack.cfg --org STAGING --user-role <"user", "reader"> --user-email <users email>
```

## add_remove_user.py


### Usage: Add user to organization 
---

```bash
python3 add_remove_user.py --config_file threatstack.cfg --add_user --id <exiting user id>  
```

### Usage: Add user to organization with multiple orgs in config
---

```bash
python3 add_remove_user.py --config threatstack.cfg --org STAGING --add_user --id <exiting user id>  
```

### Usage: Delete user from organization 
---

```bash
python3 add_remove_user.py --config_file threatstack.cfg --delete_user --id <exiting user id>  
```

### Usage: Delete user to organization with multiple orgs in config
---

```bash
python3 add_remove_user.py --config threatstack.cfg --org STAGING --delete_user --id <exiting user id>  
```


##  get_users.py
This Python3 script is used to get Users for a single organization and write them to CSV. 
```
role,ssoEnabled,displayName,userEnabled,lastAuthenticatedAt,mfaEnabled,id,email
```

### Usage: Return all Users from the default organization
---

```bash
python3 get_users.py --config threatstack.cfg
```

### Usage: Return all Users from an alternate organization
---

```bash
python3 get_users.py --config threatstack.cfg --org STAGING
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