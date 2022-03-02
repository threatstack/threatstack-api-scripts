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
    Fetch all agents for a given organization and write the results to .csv

    Additional resources:
    https://apidocs.threatstack.com/v2/rest-api-v2/authentication
    https://github.com/threatstack/rest-api-examples
"""


import requests
import argparse
import configparser
import os
import re
import sys
import csv

from mohawk import Sender
from pprint import pprint
from datetime import date


def get_args():
    """
    Get arguments from the CLI as well as the configuration file.
    Returns: 
    user_id, api_key, org_id, org_name (str)
    debug, quiet (bool)
    """
    parser = argparse.ArgumentParser(
        description="Fetch all Threat Stack agents for a given organization and write the results to CSV."
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

    # Mutually exclusive verbosity
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--quiet", action="store_true", help="Disable CLI logging.")
    verbosity.add_argument(
        "--debug", action="store_true", help="Enable additional debug CLI logging."
    )

    cli_args = parser.parse_args()

    config_file = cli_args.config_file
    org_config = cli_args.org_config
    quiet = cli_args.quiet
    debug = cli_args.debug

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

    return user_id, api_key, org_id, org_name, debug, quiet


def get_agents(
    credentials,
    BASE_PATH,
    org_id,
    OUTPUT_FILE,
    debug=False,
    quiet=False,
    token=None,
):
    CONTENT_TYPE = "application/json"
    METHOD = "GET"

    if token is None:
        URI_PATH = "agents?status=online"
    else:
        URI_PATH = "agents?status=online" + "&token=" + token

    URL = BASE_PATH + URI_PATH

    try:
        sender = Sender(credentials, URL, METHOD, always_hash_content=False, ext=org_id)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(-1)

    response = requests.get(
        URL,
        headers={"Authorization": sender.request_header, "Content-Type": CONTENT_TYPE,},
    )
    if not response.ok:
        print("Request returned status: " + str(response.status_code) + ", exiting.")
        pprint(response)
        sys.exit(-1)

    try:
        agent_json = response.json()
    except:
        print("Failed to decode API JSON response, exiting.")
        pprint(response)
        sys.exit(-1)

    if not "agents" in agent_json:
        print(
            "Malformed JSON object received - expected 'agents' key in response. Exiting."
        )
        pprint(agent_json)
        sys.exit(-1)

    agents = agent_json["agents"]
    num_agents = len(agents)
    if not num_agents >= 1:
        print("0 agents found, exiting.")
        sys.exit()

    if not quiet:
        print("Returned", num_agents, "agents.")

    AGENT_KEYS = [
        "id",
        "instanceId",
        "status",
        "createdAt",
        "lastReportedAt",
        "version",
        "name",
        "description",
        "hostname",
        "tags",
        "agentType",
        "osVersion",
        "kernel",
    ]

    # Write the agents out to the CSV file
    with open(OUTPUT_FILE, "a") as f:
        w = csv.writer(f)
        agents_list = []
        for agent in agents:
            agent_info = {}
            ipAddressList = []
            for key, val in agent.items():
                if key == "ipAddresses":
                    for addrType, ipAddresses in agent["ipAddresses"].items():
                        # Exclude link_local
                        if addrType == "private" or addrType == "public":
                            for addr in ipAddresses:
                                # Exclude localhost
                                if addr != "127.0.0.1/8" and addr != "::1/128":
                                    ipAddressList.append(addr)

                    agent_info[key] = ipAddressList
                elif key == "agentModuleHealth":
                    if debug:
                        print(key, ":", val)
                        agent_info[key] = key + ":" + str(val)
                    else:
                        if val is None:
                            agent_info[key] = ""
                        else:
                            agent_info[key] = val["isHealthy"]
                else:
                    if key in AGENT_KEYS:
                        if debug:
                            print(key, ":", val)
                            agent_info[key] = key + ":" + str(val)
                        else:
                            agent_info[key] = val
                    else:
                        print("Unexpected key,val pair: ", key, val)

            if agent_info:
                agents_list.append(agent_info)
                w.writerow(agent_info.values())

    if agents_list and not quiet:
        print(len(agents_list), "agents written to file.")

    if "paginationToken" in agent_json:
        if agent_json["paginationToken"] != None:
            if debug:
                print("Found pagination token.")
            paginationToken = agent_json["paginationToken"]
            return paginationToken
        else:
            return None

    if "token" in agent_json:
        if agent_json["token"] != None:
            if debug:
                print("Found pagination token.")
            paginationToken = agent_json["token"]
            return paginationToken
        else:
            return None
    return None


def main():
    timestamp = date.today().isoformat()
    user_id, api_key, org_id, org_name, debug, quiet = get_args()

    OUTPUT_FILE = "agents" + "-" + org_name + "-" + timestamp + ".csv"

    BASE_PATH = "https://api.threatstack.com/v2/"

    credentials = {"id": user_id, "key": api_key, "algorithm": "sha256"}

    with open(OUTPUT_FILE, "w") as f:
        w = csv.writer(f)

        # Write header
        HEADER = [
            "agentId",
            "instanceId",
            "status",
            "CreatedAt",
            "LastReportedAt",
            "version",
            "name",
            "description",
            "hostname",
            "ipAddresses",
            "tags",
            "agentType",
            "osVersion",
            "kernel",
            "isHealthy",
        ]
        w.writerow(HEADER)

    token = get_agents(
        credentials, BASE_PATH, org_id, OUTPUT_FILE, debug, quiet
    )
    while token is not None:
        token = get_agents(
            credentials, BASE_PATH, org_id, OUTPUT_FILE, debug, quiet, token
        )


if __name__ == "__main__":
    main()
