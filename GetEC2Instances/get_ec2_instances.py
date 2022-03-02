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
    List EC2 instances

    Description:
        Lists EC2 instances in a CSV file.
        Modify threatstack.cfg with API parameters


    https://apidocs.threatstack.com/v2/rest-api-v2/authentication
    https://github.com/threatstack/rest-api-examples

"""

import argparse
import configparser
import datetime
import os
import re
import sys
import time

import pandas

import threatstack


class Servers(object):
    def __init__(
        self,
        id,
        kernelId,
        instanceType,
        privateDnsName,
        privateIpAddress,
        group,
        subnetId,
        keyName,
        region,
        launchTime,
        imageId,
        architecture,
        publicDnsName,
        publicIpAddress,
        vpcId,
        awsProfile,
        monitored,
        tags,
        state,
        stateCode,
        ID,
        Status,
        createdAt,
        lastReportedAt,
        version,
        name,
        description,
        hostName,
        isContainer,
        kernel,
        osVersion,
    ):
        self.id = id
        self.kernelId = kernelId
        self.instanceType = instanceType
        self.privateDnsName = privateDnsName
        self.privateIpAddress = privateIpAddress
        self.group = group
        self.subnetId = subnetId
        self.keyName = keyName
        self.region = region
        self.launchTime = launchTime
        self.imageId = imageId
        self.architecture = architecture
        self.publicDnsName = publicDnsName
        self.publicIpAddress = publicIpAddress
        self.vpcId = vpcId
        self.awsProfile = awsProfile
        self.monitored = monitored
        self.tags = tags
        self.state = state
        self.stateCode = stateCode
        self.ID = ID
        self.Status = Status
        self.createdAt = createdAt
        self.lastReportedAt = lastReportedAt
        self.version = version
        self.name = name
        self.description = description
        self.hostName = hostName
        self.isContainer = isContainer
        self.kernel = kernel
        self.osVersion = osVersion

    def as_dict(self):
        return {
            "id": self.id,
            "kernelId": self.kernelId,
            "instanceType": self.instanceType,
            "privateDnsName": self.privateDnsName,
            "privateIpAddress": self.privateIpAddress,
            "groups": self.group,
            "subnetId": self.subnetId,
            "keyName": self.keyName,
            "region": self.region,
            "launchTime": self.launchTime,
            "imageId": self.imageId,
            "architecture": self.architecture,
            "publicDnsName": self.publicDnsName,
            "publicIpAddress": self.publicIpAddress,
            "vpcId": self.vpcId,
            "awsProfile": self.awsProfile,
            "keyName": self.keyName,
            "monitored": self.monitored,
            "tags": self.tags,
            "state": self.state,
            "stateCode": self.stateCode,
            "ID": self.ID,
            "Status": self.Status,
            "createdAt": self.createdAt,
            "lastReportedAt": self.lastReportedAt,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "hostName": self.hostName,
            "isContainer": self.isContainer,
            "kernel": self.kernel,
            "osVersion": self.osVersion,
        }


class Group(object):
    def __init__(self, ID, Name, Value, Instance):
        self.ID = ID
        self.Name = Name

    def as_dict(self):
        return {"ID": self.ID, "Name": self.Name}


class awsProfile(object):
    def __init__(
        self,
        ID,
        OrgName,
        Description,
    ):
        self.ID = ID
        self.OrgName = OrgName
        self.Description = Description

    def as_dict(self):
        return {"ID": self.ID, "OrgName": self.OrgName, "Description": self.Description}


class tags(object):
    def __init__(self, Source, Key, Value, Instance):
        self.Source = Source
        self.Key = Key
        self.Value = Value
        self.Instance = Instance

    def as_dict(self):
        return {
            "Source": self.Source,
            "Key": self.Key,
            "Value": self.Value,
            "Instance": self.Instance,
        }


class agents(object):
    def __init__(
        self,
        ID,
        Status,
        createdAt,
        lastReportedAt,
        version,
        name,
        description,
        hostName,
        isContainer,
        kernel,
        osVersion,
    ):
        self.ID = ID
        self.Status = Status
        self.createdAt = createdAt
        self.lastReportedAt = lastReportedAt
        self.version = version
        self.name = name
        self.description = description
        self.hostName = hostName
        self.isContainer = isContainer
        self.kernel = kernel
        self.osVersion = osVersion

    def as_dict(self):
        return {
            "ID": self.ID,
            "Status": self.Status,
            "createdAt": self.createdAt,
            "lastReportedAt": self.lastReportedAt,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "hostName": self.hostName,
            "isContainer": self.isContainer,
            "kernel": self.kernel,
            "osVersion": self.osVersion,
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

    # Mutually exclusive alert status
    status = parser.add_mutually_exclusive_group()
    status.add_argument("--monitored", action="store_true")
    status.add_argument("--unmonitored", action="store_false")

    cli_args = parser.parse_args()

    config_file = cli_args.config_file
    org_config = cli_args.org_config
    monitored = cli_args.monitored
    unmonitored = cli_args.unmonitored

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

    return user_id, api_key, org_id, org_name, monitored, unmonitored


def print_parsed_args(
    user_id, api_key, org_id, org_name, state, monitored, unmonitored
):
    """
    This function is used to print the incoming args

    Parameters:
    user_id (str) : User id used for Threatstack API
    api_key (str) : Api Key used for Threatstack API
    org_id (str) : org id used for Threatstack API
    org_name (str) : org name used for Threatstack API
    state (string): 'all', 'running', 'stopped', 'terminated'
    monitored (bool) : Monitored is if the agent is installed and monitored in TS
    unmonitored (bool) : Unmonitored if the agent is not installed and monitored in TS
    """

    print("user_id: " + user_id)
    print("api_key: " + api_key)
    print("org_id: " + org_id)
    print("org_name: " + org_name)
    print("monitored: " + str(monitored))
    print("unmonitored: " + str(unmonitored))


def get_ec2_instances(userid, apikey, orgid, OUTPUT_FILE, monitored):
    """
    This function is used get all ec2 instances data based on monitored status
    and state of the instances.

    Parameters:
    userid (str) : User id used for Threatstack API
    apikey (str) : Api Key used for Threatstack API
    orgid (str) : org id used for Threatstack API
    OUTPUT_FILE (str) : output file name to write ec2 instance data to.
    monitored (bool) : Monitored is if the agent is installed and monitored in TS
    """
    allorgec2 = []
    tsclient = threatstack.ApiClient(
        user_id=userid, org_id=orgid, api_key=apikey, retry=5
    )
    if monitored:
        querystring = "aws/ec2?monitored=true&verbose=true"
    else:
        querystring = "aws/ec2?monitored=false&verbose=true"
    server_list = tsclient.get_list(querystring)
    servercount = 0
    while server_list:

        for server in server_list.data:

            if monitored:
                allorgec2.append(
                    Servers(
                        server["id"],
                        server["kernelId"],
                        server["instanceType"],
                        server["privateDnsName"],
                        server["privateIpAddress"],
                        server["groups"],
                        server["subnetId"],
                        server["keyName"],
                        server["region"],
                        server["launchTime"],
                        server["imageId"],
                        server["architecture"],
                        server["publicDnsName"],
                        server["publicIpAddress"],
                        server["vpcId"],
                        server["awsProfile"],
                        server["monitored"],
                        server["tags"],
                        server["state"],
                        server["stateCode"],
                        server["agents"][0]["id"],
                        server["agents"][0]["status"],
                        server["agents"][0]["createdAt"],
                        server["agents"][0]["lastReportedAt"],
                        server["agents"][0]["version"],
                        server["agents"][0]["name"],
                        server["agents"][0]["description"],
                        server["agents"][0]["hostname"],
                        server["agents"][0]["isContainerAgent"],
                        server["agents"][0]["kernel"],
                        server["agents"][0]["osVersion"],
                    )
                )
            else:
                #  unmanaged instances don't have an agent so we expect no agent info
                #  thus the 11 empty ""
                allorgec2.append(
                    Servers(
                        server["id"],
                        server["kernelId"],
                        server["instanceType"],
                        server["privateDnsName"],
                        server["privateIpAddress"],
                        server["groups"],
                        server["subnetId"],
                        server["keyName"],
                        server["region"],
                        server["launchTime"],
                        server["imageId"],
                        server["architecture"],
                        server["publicDnsName"],
                        server["publicIpAddress"],
                        server["vpcId"],
                        server["awsProfile"],
                        server["monitored"],
                        server["tags"],
                        server["state"],
                        server["stateCode"],
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                    )
                )
            servercount += 1
        if server_list.token:
            querystringtoken = querystring + "&token=" + server_list.token
            server_list = tsclient.get_list(querystringtoken)
            time.sleep(0.09)
        else:
            server_list = None

    allserversDF = pandas.DataFrame([x.__dict__ for x in allorgec2])
    allserversDF.to_csv(OUTPUT_FILE, index=False)


def main():
    timestamp = f"{datetime.datetime.now():%Y-%m-%d-%H-%M}"

    (
        user_id,
        api_key,
        org_id,
        org_name,
        monitored,
        unmonitored,
    ) = get_args()

    if monitored:
        OUTPUT_FILE = (
            "EC2Instances" + "-" + org_name + "-monitored-" + timestamp + ".csv"
        )
        get_ec2_instances(user_id, api_key, org_id, OUTPUT_FILE, monitored)
    else:
        OUTPUT_FILE = (
            "EC2Instances" + "-" + org_name + "-unmonitored-" + timestamp + ".csv"
        )
        get_ec2_instances(user_id, api_key, org_id, OUTPUT_FILE, unmonitored)


if __name__ == "__main__":
    main()
