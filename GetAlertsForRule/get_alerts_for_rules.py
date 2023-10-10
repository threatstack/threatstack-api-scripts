#   Copyright (c) 2022 F5, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
    Fetch all Alerts for a single rule or all rules in a given organization for a set 
    number of days and then write the results to .csv

    Additional resources:
    https://pkg.threatstack.com/api/index.html#tag/Alerts
"""

import argparse
import configparser
from datetime import datetime, timezone, timedelta
import os
import re
import sys
import time

import pandas

import threatstack


def get_args():
    """
    Get arguments from the CLI as well as the configuration file.
    Returns:
    user_id, api_key, org_id, org_name, org_name, rule_id (str)
    start, end (iso date)
    """
    parser = argparse.ArgumentParser(
        description="Fetch all Threat Stack Rules and Suppressions for a given organization and write the results to CSV."
    )

    parser.add_argument(
        "--alert-status",
        dest="alert_status",
        choices=["active", "dismissed"],
        required=False,
        default="active",
    )

    parser.add_argument(
        "--rule-id",
        dest="rule_id",
        help="Rule Id to get all alerts for",
        required=False,
        default=None,
    )

    parser.add_argument(
        "--config_file",
        dest="config_file",
        help="Override the default threatstack.cfg file.",
        required=False,
        default="threatstack.cfg",
    )

    parser.add_argument(
        "--org",
        dest="org_config",
        help="Which organization's configuration to load from the config file.",
        required=False,
        default="DEFAULT",
    )

    parser.add_argument(
        "--start-date",
        dest="start_date",
        help="Start datetime of the range",
        required=False,
        default="DEFAULT",
    )

    parser.add_argument(
        "--end-date",
        dest="end_date",
        help="End datetime of the range",
        required=False,
        default="DEFAULT",
    )

    parser.add_argument(
        "--filename",
        dest="filename",
        help="Name of the file you wish to append to",
        required=False,
        default="DEFAULT",
    )

    parser.add_argument(
        "daycount",
        choices=[
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "15",
            "30",
            "60",
            "68",
            "90",
            "180",
            "365",
        ],
        help="Number of days previous to today to get alerts for",
    )

    cli_args = parser.parse_args()

    config_file = cli_args.config_file
    org_config = cli_args.org_config
    alert_status = cli_args.alert_status
    rule_id = cli_args.rule_id
    end_date = cli_args.end_date if cli_args.end_date != "DEFAULT" else datetime.isoformat(datetime.utcnow())
    numberofdays = int(cli_args.daycount)
    start = datetime.utcnow() - timedelta(days=numberofdays)
    start_date = cli_args.start_date if cli_args.start_date != "DEFAULT" else datetime.isoformat(start)
    filename = cli_args.filename

    if not os.path.isfile(filename) and filename != "DEFAULT":
        print("Unable to find file to write to: " + filename + ", exiting.")
        sys.exit(-1)
    
    if not os.path.isfile(config_file):
        print("Unable to find config file: " + config_file + ", exiting.")
        sys.exit(-1)

    config = configparser.ConfigParser()
    config.read(config_file)

    if org_config not in config:
        print("Config file does not contain config name: " + org_config + ", exiting.")
        sys.exit(-1)

    user_opts = config["USER_INFO"]
    org_opts = config[org_config]
    for config_val in ["TS_USER_ID", "TS_API_KEY"]:
        if config_val not in user_opts:
            print(
                "Config file is missing necessary value: " + config_val + ", exiting."
            )
            sys.exit(-1)
    for config_val in ["TS_ORGANIZATION_ID", "TS_ORGANIZATION_NAME"]:
        if config_val not in org_opts:
            print(
                "Config file is missing necessary value: " + config_val + ", exiting."
            )
            sys.exit(-1)

    user_id = user_opts["TS_USER_ID"]
    api_key = user_opts["TS_API_KEY"]

    org_id = org_opts["TS_ORGANIZATION_ID"]
    # sanitize the provided organization name for use in the CSV filename
    tmp_org_name = re.sub("[\W_]+", "_", org_opts["TS_ORGANIZATION_NAME"])
    org_name = re.sub("[^A-Za-z0-9]+", "", tmp_org_name)

    return (
        user_id,
        api_key,
        org_id,
        org_name,
        alert_status,
        start_date,
        end_date,
        rule_id,
        filename,
    )


def print_parsed_args(
    user_id, api_key, org_id, org_name, alert_status, start, end_date, rule_id, filename
):
    """
    This function is used to print the incoming args

    Parameters:
    user_id (str) : User id used for Threat Stack API
    api_key (str) : Api Key used for Threat Stack API
    org_id (str) : org id used for Threat Stack API
    org_name (str) : org name used for Threat Stack API
    alert_status(str) : Active or Dissmissed alerts
    start (date) : start date
    end (date) : date of today
    rule_id (str) : rule id we are processing for
    filename (str): optoinal filename to append to 
    """

    print("user_id: " + user_id)
    print("api_key: " + api_key)
    print("org_id: " + org_id)
    print("org_name: " + org_name)
    print("alert_status: " + alert_status)
    print("start: " + str(start))
    print("end: " + str(end_date))
    print("rule_id: " + str(rule_id))
    print("filename: " + filename)


def write_out_to_disk(data, status, rule_id, org_name, date, filename, writeHeader):
    df = pandas.DataFrame(data)
    df = df.replace(r"\\n", " ", regex=True)
    df = df.replace(r"\\r", " ", regex=True)

    alertfile = ""
    header = writeHeader
    
    if filename != "DEFAULT":
        alertfile = filename
        header = False
    else:
        if rule_id is None:
            alertfile = f"{org_name}-{status}-{date}.csv"
        else:
            alertfile = f"{org_name}-{rule_id}-{status}-{date}.csv"

    if status == "dismissed":
        print(f"Writing alerts: {len(data)}, Rule status: {status}")

        if rule_id is None:    
            df.to_csv(alertfile, mode='a', header=header, index=False)
        else:
            dfonlymatchingruleid = df[df["ruleId"] == rule_id]
            dfonlymatchingruleid.to_csv(alertfile, index=False, header=header, mode='a')
    else:   
        print(f"Writing alerts: {len(data)}, Rule status: {status}")

        if rule_id is None:
            df.to_csv(alertfile, mode='a', header=header, index=False)
        else:
            dfonlymatchingruleid = df[df["ruleId"] == rule_id]
            dfonlymatchingruleid.to_csv(alertfile, mode='a', header=header, index=False)



def get_alerts(userid, apikey, orgid, org_name, alert_status, start, end_date, rule_id, filename):
    """
    This function is used to get all the alerts for a specfic org and rule id
    This is then writen out to a csv file

    Parameters:
    user_id (str) : User id used for Threat Stack API
    api_key (str) : Api Key used for Threat Stack API
    org_id (str) : org id used for Threat Stack API
    org_name (str) : org name used for Threat Stack API
    alert_status(str) : Active or Dissmissed alerts
    start (date) : start date
    end (date) : date of today
    rule_id (str) : rule id we are processing for
    filename (str): optoinal filename to append to instead of creating a new file

    """
    alertstatus = alert_status
    processed_count = 0
    all_alerts = []
    firstTime = True
    date = f"{datetime.utcnow():%Y-%m-%d-%H-%M}"

    uaclient = threatstack.ApiClient(
        user_id=userid, org_id=orgid, api_key=apikey, retry=5
    )
    if rule_id is None:
        getliststring = f"alerts?status={alertstatus}&from={start}&until={end_date}"
    else:
        getliststring = f"alerts?status={alertstatus}&ruleId={rule_id}&from={start}&until={end_date}"
        
    print(getliststring)

    alert_list = uaclient.get_list(getliststring)

    while alert_list:
        # print(alert_list.data)
        print("Adding alert", start, end_date, processed_count)

        for alert in alert_list.data:
            processed_count += 1
            all_alerts.append(alert)

        write_out_to_disk(alert_list.data, alert_status, rule_id, org_name, date, filename, firstTime)
        firstTime = False

        if alert_list.token:
            if rule_id is None:
                querystring = f"alerts?status={alertstatus}&from={start}&until={end_date}&token={alert_list.token}"
            else:
                querystring = f"alerts?status={alertstatus}&ruleId={rule_id}&from={start}&until={end_date}&token={alert_list.token}"

            alert_list = uaclient.get_list(querystring)
            time.sleep(0.09)

        else:
            alert_list = None


def main():

    # Call get_args and get set the values for next function calls
    user_id, api_key, org_id, org_name, alert_status, start, end, rule_id, filename = get_args()

    # Print out the ags
    print_parsed_args(
        user_id, api_key, org_id, org_name, alert_status, start, end, rule_id, filename
    )

    # Now go call getalerts to do it's api calls
    get_alerts(
        user_id, api_key, org_id, org_name, alert_status, str(start), str(end), rule_id, filename
    )


if __name__ == "__main__":
    main()
