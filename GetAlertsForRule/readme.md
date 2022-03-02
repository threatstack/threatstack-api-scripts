
#  GetAlertsForRules
This Python3 script is used to get alerts either based on day count or Rule ID and day count and write them to CSV.

```
    Parameters:
    alert_status(str) : Active or Dissmissed alerts
    count(int) : Number of days back from today
    rule_id (str) : Rule id we are processing for
```

## Usage: Return all active alerts from the default organization
---
This will return all active alerts from the past day (1 day back)
```bash
python3 get_alerts_for_rules.py 1
```

## Usage: Return all active alerts from an alternate organization
---
This will return all active alerts from the past day (1 day back)
```bash
python3 get_alerts_for_rules.py --org STAGING 1
```

## Usage: Return all dismissed alerts
---
This will return all dismissed alerts from the past day (1 day back)

```bash
python3 get_alerts_for_rules.py --alert-status dismissed 1
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