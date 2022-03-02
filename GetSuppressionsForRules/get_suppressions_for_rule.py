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
    Fetch all suppressions for all rules in a given organization and write the 
    results to .csv

    Additional resources:
    https://github.com/threatstack/rest-api-examples
"""

import argparse
import configparser
import datetime
import os
import re
import sys

import pandas

import threatstack

class RuleDetails(object):
    def __init__(
        self,
        RuleSetId,
        RuleSetName,
        Id,
        Name,
        Title,
        Description,
        Enabled,
        Severity,
        Supperssions,
    ):
        self.RuleSetId = RuleSetId
        self.RuleSetName = RuleSetName
        self.Id = Id
        self.Name = Name
        self.Title = Title
        self.Description = Description
        self.Enabled = Enabled
        self.Severity = Severity
        self.Supperssions = Supperssions

    def as_dict(self):
        return {
            "RuleSetId": self.RuleSetId,
            "RuleSetName": self.RuleSetName,
            "Id": self.Id,
            "Name": self.Name,
            "Title": self.Title,
            "Description": self.Description,
            "Enabled": self.Enabled,
            "Severity": self.Severity,
            "Suppressions": self.Supperssions,
        }


def get_args():
    """
    Get arguments from the CLI as well as the configuration file.
    Returns:
    user_id, api_key, org_id, org_name (str)

    """
    parser = argparse.ArgumentParser(
        description="Fetch all Threat Stack Rules and Suppressions for a given organization and write the results to CSV."
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

    cli_args = parser.parse_args()

    config_file = cli_args.config_file
    org_config = cli_args.org_config

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

    return user_id, api_key, org_id, org_name


def print_parsed_args(user_id, api_key, org_id, org_name):
    """
    This function is used to print the incoming args

    Parameters:
    user_id (str) : User id used for Threat Stack API
    api_key (str) : Api Key used for Threat Stack API
    org_id (str) : org id used for Threat Stack API
    org_name (str) : org name used for Threat Stack API

    """

    print("user_id: " + user_id)
    print("api_key: " + api_key)
    print("org_id: " + org_id)
    print("org_name: " + org_name)


def get_suppressions(userid, apikey, orgid, org_name):
    """
    This function is used to get all the suppressions for a specfic org
    This is then writen out to a csv file

    Parameters:
    user_id (str) : User id used for Threat Stack API
    api_key (str) : Api Key used for Threat Stack API
    org_id (str) : org id used for Threat Stack API
    org_name (str) : org name used for Threat Stack API


    """
    all_org_rules = []

    uaclient = threatstack.ApiClient(
        user_id=userid, org_id=orgid, api_key=apikey, retry=5
    )

    ruleset_list = uaclient.get_list("rulesets")

    while ruleset_list:

        for rulesets in ruleset_list.data:
            # Get Details for each ruleset
            print("Getting ruleset: " + rulesets["name"])

            querystring = "rulesets/" + rulesets["id"] + "/rules"

            rules = uaclient.get_list(querystring)
            for rule in rules.data:
                if not rule["suppressions"]:
                    all_org_rules.append(
                        RuleDetails(
                            rulesets["id"],
                            rulesets["name"],
                            rule["id"],
                            rule["name"],
                            rule["title"],
                            str(rule["alertDescription"]).replace("\n", " "),
                            rule["enabled"],
                            rule["severityOfAlerts"],
                            "",
                        )
                    )
                else:
                    for suppression in rule["suppressions"]:
                        all_org_rules.append(
                            RuleDetails(
                                rulesets["id"],
                                rulesets["name"],
                                rule["id"],
                                rule["name"],
                                rule["title"],
                                str(rule["alertDescription"]).replace("\n", " "),
                                rule["enabled"],
                                rule["severityOfAlerts"],
                                suppression,
                            )
                        )
            print("Finished getting all rules in: " + rulesets["name"])
            ruleset_list = None

    allrulesDF = pandas.DataFrame([x.__dict__ for x in all_org_rules])

    rulefile = (
        org_name + "-All-Rules-" + f"{datetime.datetime.now():%Y-%m-%d-%H-%M}" + ".csv"
    )
    allrulesDF.to_csv(rulefile, index=False)


def main():

    # Call GetArgs and get set the values for next function calls
    user_id, api_key, org_id, org_name = get_args()

    # Print out the ags
    print_parsed_args(user_id, api_key, org_id, org_name)

    # Now go call getsuppressions to do it's api calls
    get_suppressions(user_id, api_key, org_id, org_name)


if __name__ == "__main__":
    main()
