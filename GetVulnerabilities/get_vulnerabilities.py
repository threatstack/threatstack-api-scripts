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
    Fetch all vulnerabilities for all rules in a given organization and write the 
    results to .csv

    Additional resources:
    https://github.com/threatstack/rest-api-examples
"""

import argparse
import configparser
from datetime import date
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
    user_id, api_key, org_id, org_name (str)

    """
    parser = argparse.ArgumentParser(
        description="Fetch all Threat Stack Rules and vulnerabilities for a given organization and write the results to CSV."
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
        "--notices",
        dest="notices",
        action="store_true",
        help="Pull only vulns that have security notices",
        required=False,
        default=False,
    )

    cli_args = parser.parse_args()

    config_file = cli_args.config_file
    org_config = cli_args.org_config
    notices = cli_args.notices

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

    return user_id, api_key, org_id, org_name, notices


def print_parsed_args(user_id, api_key, org_id, org_name, notices):
    """
    This function is used to print the incoming args

    Parameters:
    user_id (str) : User id used for Threat Stack API
    api_key (str) : Api Key used for Threat Stack API
    org_id (str) : org id used for Threat Stack API
    org_name (str) : org name used for Threat Stack API
    notices (boolean) : whether to only get vulns with security notices
    """

    print("user_id: " + user_id)
    print("api_key: " + api_key)
    print("org_id: " + org_id)
    print("org_name: " + org_name)
    print("notices: " + str(notices))


def get_vulnerabilities(userid, apikey, orgid, org_name, notices):
    """
    This function is used to get all the vulnerabilities for a specfic org
    This is then writen out to a csv file

    Parameters:
    user_id (str) : User id used for Threat Stack API
    api_key (str) : Api Key used for Threat Stack API
    org_id (str) : org id used for Threat Stack API
    org_name (str) : org name used for Threat Stack API
    notices (boolean) : whether to only get vulns with security notices
    """
    all_vulns = []
    enhanced_vuln = None
    ec2_servers = {}
    timestamp = date.today().isoformat()
    vulnfile = "Vulns" + "-" + org_name + "-" + timestamp + ".csv"
    uaclient = threatstack.ApiClient(
        user_id=userid, org_id=orgid, api_key=apikey, retry=5
    )

    # get vulns based on notices
    if notices == True:
        vuln_query_string = "vulnerabilities?status=active&hasSecurityNotices=true"
        vulnfile = "Vulns" + "-" + org_name + "-SecurityNotices-" + timestamp + ".csv"
    else:
        vuln_query_string = "vulnerabilities?status=active"
        vulnfile = "Vulns" + "-" + org_name + "-" + timestamp + ".csv"

    ec2_query_string = "aws/ec2?monitored=true&verbose=true"
    ec2_server_list_data = uaclient.get_list(ec2_query_string)
    vuln_list = uaclient.get_list(vuln_query_string)

    while ec2_server_list_data:
        if ec2_server_list_data.token:
            print("token is: '" + ec2_server_list_data.token + "'")
            ec2_query_string_token = (
                ec2_query_string + "&token=" + ec2_server_list_data.token
            )
            print("query String is: '" + ec2_query_string_token + "'")
            for server in ec2_server_list_data.data:
                ec2_servers[server["agents"][0]["id"]] = server

            ec2_server_list_data = uaclient.get_list(ec2_query_string_token)
        else:
            for server in ec2_server_list_data.data:
                ec2_servers[server["agents"][0]["id"]] = server
            ec2_server_list_data = None
            print("token is blank")
        time.sleep(0.09)

    # print(ec2_servers)

    while vuln_list:
        print("Adding vulns")

        for vuln in vuln_list.data:
            # Add the agent id to the top level of the dictionary
            vuln["agentId"] = vuln["agents"][0]["agentId"]
            # print(vuln["agentId"])
            # if vuln agent id is in ec2 servers add that to the enchanced_vulns
            if vuln["agentId"] in ec2_servers:
                server = ec2_servers[vuln["agentId"]]
                enhanced_vuln = {**vuln, **server}

            if enhanced_vuln is not None:
                all_vulns.append(enhanced_vuln)
                enhanced_vuln = None
            else:
                all_vulns.append(vuln)

        if vuln_list.token:
            print("token is: " + vuln_list.token)
            querystring = vuln_query_string + "&token=" + vuln_list.token
            vuln_list = uaclient.get_list(querystring)
        else:
            vuln_list = None
        # Add all the vulns into pandas and convert to CSV

    df = pandas.DataFrame(all_vulns)
    df.to_csv(vulnfile, index=False)
    # print(vul_list.data)


def main():

    # Call GetArgs and get set the values for next function calls
    user_id, api_key, org_id, org_name, notices = get_args()

    # Print out the ags
    print_parsed_args(user_id, api_key, org_id, org_name, notices)

    # Now go call getvulnerabilities to do it's api calls
    get_vulnerabilities(user_id, api_key, org_id, org_name, notices)


if __name__ == "__main__":
    main()
