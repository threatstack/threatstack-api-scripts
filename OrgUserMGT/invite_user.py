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
    Threat Stack User managment

    Description:
        This script is for inviting of users to a Threat Stack org.


    https://apidocs.threatstack.com/v2/rest-api-v2/authentication
    https://github.com/threatstack/rest-api-examples

"""

import argparse
import configparser
import datetime
import os
import re
import sys
import json
import threatstack


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

    parser.add_argument(
        "--user-role",
        dest="user_role",
        choices=["user", "reader"],
        required=True,
        default="user",
    )

    parser.add_argument(
        "--user-email",
        dest="user_email",
        required=True,
    )

    cli_args = parser.parse_args()

    config_file = cli_args.config_file
    org_config = cli_args.org_config
    user_role = cli_args.user_role
    user_email = cli_args.user_email

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

    return user_id, api_key, org_id, org_name, user_role, user_email


def print_parsed_args(user_id, api_key, org_id, org_name, user_role, user_email):
    """
    This function is used to print the incoming args

    Parameters:
    user_id (str) : User id used for Threatstack API
    api_key (str) : Api Key used for Threatstack API
    org_id (str) : org id used for Threatstack API
    org_name (str) : org name used for Threatstack API
    user_role (string): "user", "reader"
    user_email (string): the email to be invited to an org

    """

    print("user_id: " + user_id)
    print("api_key: " + api_key)
    print("org_id: " + org_id)
    print("org_name: " + org_name)
    print("user_role: " + user_role)
    print("user_email: " + user_email)


def emailverify(email):
    pat = "^\S+@\S+\.\S+$"
    if re.match(pat, email):
        return True
    return False


def invite_user(userid, apikey, orgid, user_role, user_email):

    tsclient = threatstack.ApiClient(
        user_id=userid, org_id=orgid, api_key=apikey, retry=5
    )
    invite = "organizations/invites"
    data = {}
    data["role"] = user_role
    data["email"] = user_email

    tsclient.post(invite, json.dumps(data))


def main():
    timestamp = f"{datetime.datetime.now():%Y-%m-%d-%H-%M}"

    (user_id, api_key, org_id, org_name, user_role, user_email) = get_args()

    if emailverify(user_email):
        invite_user(user_id, api_key, org_id, user_role, user_email)
    else:
        print("email failed to verify ", user_email)
        exit(-50)


if __name__ == "__main__":
    main()
