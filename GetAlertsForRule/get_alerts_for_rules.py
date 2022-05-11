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
    end_date = datetime.isoformat(datetime.utcnow())
    numberofdays = int(cli_args.daycount)
    start = datetime.utcnow() - timedelta(days=numberofdays)
    start_date = datetime.isoformat(start)
    
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
    )


def print_parsed_args(
    user_id, api_key, org_id, org_name, alert_status, start, end_date, rule_id
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

    """

    print("user_id: " + user_id)
    print("api_key: " + api_key)
    print("org_id: " + org_id)
    print("org_name: " + org_name)
    print("alert_status: " + alert_status)
    print("start: " + str(start))
    print("end: " + str(end_date))
    print("rule_id: " + str(rule_id))


def get_alerts(userid, apikey, orgid, org_name, alert_status, start, end_date, rule_id):
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

    """
    alertstatus = alert_status
    processed_count = 0
    all_alerts = []

    uaclient = threatstack.ApiClient(
        user_id=userid, org_id=orgid, api_key=apikey, retry=5
    )
    if rule_id is None:
        getliststring = (
            "alerts?status=" + alertstatus + "&from=" + start + "&until=" + end_date
        )
    else:
        getliststring = (
            "alerts?status="
            + alertstatus
            + "&ruleId="
            + rule_id
            + "&from="
            + start
            + "&until="
            + end_date
        )
    print(getliststring)

    alert_list = uaclient.get_list(getliststring)

    while alert_list:
        # print(alert_list.data)
        print("Adding alert", start, end_date, processed_count)

        for alert in alert_list.data:
            processed_count += 1
            all_alerts.append(alert)
        if alert_list.token:
            if rule_id is None:
                querystring = (
                    "alerts?status="
                    + alertstatus
                    + "&from="
                    + start
                    + "&until="
                    + end_date
                    + "&token="
                    + alert_list.token
                )
            else:
                querystring = (
                    "alerts?status="
                    + alertstatus
                    + "&ruleId="
                    + rule_id
                    + "&from="
                    + start
                    + "&until="
                    + end_date
                    + "&token="
                    + alert_list.token
                )

            alert_list = uaclient.get_list(querystring)
            time.sleep(0.09)

        else:
            alert_list = None

    df = pandas.DataFrame(all_alerts)
    df = df.replace(r"\\n", " ", regex=True)
    df = df.replace(r"\\r", " ", regex=True)
    if alert_status == "dismissed":
        print(
            "Writing alerts: ",
            start,
            end_date,
            processed_count,
            "Rule status: ",
            alertstatus,
        )

        if rule_id is None:
            alertfile = (
                org_name
                + "-"
                + alertstatus
                + "-"
                + f"{datetime.utcnow():%Y-%m-%d-%H-%M}"
                + ".csv"
            )
            df.to_csv(alertfile, index=False)
        else:
            dfonlymatchingruleid = df[df["ruleId"] == rule_id]
            alertfile = (
                org_name
                + "-"
                + rule_id
                + "-"
                + alertstatus
                + "-"
                + f"{datetime.utcnow():%Y-%m-%d-%H-%M}"
                + ".csv"
            )
            dfonlymatchingruleid.to_csv(alertfile, index=False)
    else:
        print(
            "Writing alerts: ",
            start,
            end_date,
            processed_count,
            "Rule status: ",
            alertstatus,
        )

        if rule_id is None:
            alertfile = (
                org_name
                + "-"
                + alertstatus
                + "-"
                + f"{datetime.utcnow():%Y-%m-%d-%H-%M}"
                + ".csv"
            )
            df.to_csv(alertfile, index=False)
        else:
            dfonlymatchingruleid = df[df["ruleId"] == rule_id]
            alertfile = (
                org_name
                + "-"
                + rule_id
                + "-"
                + alertstatus
                + "-"
                + f"{datetime.utcnow():%Y-%m-%d-%H-%M}"
                + ".csv"
            )
            dfonlymatchingruleid.to_csv(alertfile, index=False)


def main():

    # Call get_args and get set the values for next function calls
    user_id, api_key, org_id, org_name, alert_status, start, end, rule_id = get_args()

    # Print out the ags
    print_parsed_args(
        user_id, api_key, org_id, org_name, alert_status, start, end, rule_id
    )

    # Now go call getalerts to do it's api calls
    get_alerts(
        user_id, api_key, org_id, org_name, alert_status, str(start), str(end), rule_id
    )


if __name__ == "__main__":
    main()
