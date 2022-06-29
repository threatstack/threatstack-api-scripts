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
        This script is for listing, adding and removing users from the Threat Stack org


    https://apidocs.threatstack.com/v2/rest-api-v2/authentication
    https://github.com/threatstack/rest-api-examples

"""

import argparse
import configparser
import datetime
from email.policy import default
import os
import re
import sys
import json

import threatstack


def get_args():
    """
    Get arguments from the CLI as well as the configuration file.

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
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--add_user",
        dest="add_user",
        action="store_true",
        help="This option expects you to add a user to an Organization who already exists in another Organization",
    )
    group.add_argument(
        "--delete_user",
        dest="delete_user",
        action="store_true",
        help="This is used to remove a user from an Organization",
    )

    parser.add_argument(
        "--role",
        help="user roles are 'user' or 'reader'",
        dest="user_role",
        choices=["user", "reader"],
        default="user",
    )
    parser.add_argument(
        "--id",
        help="id of existing Threatstack user to add to this org",
        dest="user_id",
        required=False,
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

    if cli_args.add_user:
        user_role = cli_args.user_role
        org_user_id = (cli_args.user_id).strip()
        add_remove = True
        print_parsed_args(
            user_id, api_key, org_id, org_name, user_role, org_user_id, add_remove
        )
        add_remove_user(
            user_id, api_key, org_id, org_name, user_role, org_user_id, add_remove
        )
    elif cli_args.delete_user:
        user_role = cli_args.user_role
        org_user_id = (cli_args.user_id).strip()
        add_remove = False
        print_parsed_args(
            user_id, api_key, org_id, org_name, user_role, org_user_id, add_remove
        )
        add_remove_user(
            user_id, api_key, org_id, org_name, user_role, org_user_id, add_remove
        )


def print_parsed_args(
    user_id, api_key, org_id, org_name, user_role, org_user_id, add_remove
):
    """
    This function is used to print the incoming args

    Parameters:
    user_id (str) : User id used for Threatstack API
    api_key (str) : Api Key used for Threatstack API
    org_id (str) : org id used for Threatstack API
    org_name (str) : org name used for Threatstack API
    user_role (str) : user roles are 'user' or 'reader'
    org_user_id (str) :  Threat Stack User ID
    add_remove (bool) : weather to add or remove user
    """

    print("user_id: " + user_id)
    print("api_key: " + api_key)
    print("org_id: " + org_id)
    print("org_name: " + org_name)
    print("user_role: " + user_role)
    print("org_user_id: " + org_user_id)
    print("get_user: " + str(add_remove))


def add_remove_user(
    user_id, api_key, org_id, org_name, user_role, org_user_id, add_remove
):
    """
    This function is used to add or removed a user to a specfic org


    Parameters:
    user_id (str) : User id used for Threat Stack API
    api_key (str) : Api Key used for Threat Stack API
    org_id (str) : org id used for Threat Stack API
    org_name (str) : org name used for Threat Stack API
    user_role (str) : User role to be used for adding user to org
    org_user_id (str) : Threat Stack User id for specific user to be added to org
    add_remove (bool) : if True add user if False remove user
    """
    tsclient = threatstack.ApiClient(
        user_id=user_id, org_id=org_id, api_key=api_key, retry=5
    )
    if add_remove:
        useradd = "organizations/members"
        data = {}
        data["role"] = user_role
        data["id"] = org_user_id

        try:
            print("attempting to Add user: ", org_user_id)
            add_user = tsclient.post(useradd, json.dumps(data))
        except:
            print("Api call failed", useradd, add_user)

        if add_user.status_code == 200:
            print("User added")

    elif add_remove == False:
        userremove = "organizations/members/" + org_user_id

        try:
            remove_user = tsclient.delete(userremove)
        except:
            print("Api call failed", remove_user)
        if remove_user.status_code == 204:
            print("user has been removed")


def main():

    get_args()


if __name__ == "__main__":
    main()
