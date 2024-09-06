import argparse
import csv
import ipaddress
import logging.handlers
import sys

try:
    import requests

    from vat.platform import ClientV3_latest
    from vat.vectra import ClientV2_latest, _format_url
except Exception as error:
    print("\nMissing import requirements: {}\n".format(str(error)))
    sys.exit(0)

LOG = logging.getLogger(__name__)

INVALID_CHARS = ["~", "#", "$", "^", "+", "=", "<", ">", "?", ";"]
SUB_CHAR = "_"
ERRORS = list()

# Suppress Detect certificate warning
requests.packages.urllib3.disable_warnings()


def print_errors(errors):
    print("The following {} errors were encountered:".format(len(errors)))
    for err in errors:
        print("{}".format(err))


def ip_subnet(subnet_string):
    """
    Called with string that represents an IP subnet with CIDR or netmask in dotted decimal format

    Validates string represents valid subnet and removes host bits
    Returns string representation of subnet in CIDR format
    :param subnet_string: string representing subnet in CIDR w.x.y.z/n or netmask w.x.y.z/aa.bb.cc.dd format
    :return: returns string representation of subnet in CIDR format
    """
    global ERRORS
    try:
        ipaddress.IPv4Network(subnet_string)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as sub_error:
        LOG.info("Subnet {} format error, {}".format(subnet_string, sub_error))
        ERRORS.append("Subnet {} format error, {}".format(subnet_string, sub_error))
        return
    except ValueError as sub_error:
        ERRORS.append(
            "Subnet {} has host bits, removing. {}".format(subnet_string, sub_error)
        )
        LOG.info("{}, removing host bits".format(sub_error))
    subnet = ipaddress.IPv4Network(subnet_string, strict=False)
    return str(subnet)


def sub_bad_chars(string, sub=SUB_CHAR):
    """
    Substitute unsupported characters in string representing group

    :param string: original string
    :param sub:  substitution character, default defined in SUB_CHAR
    :return:  returns the original string with any illegal characters substituted
    """
    for bad_char in INVALID_CHARS:
        string = string.replace(bad_char, sub)
    return string


def group_exists(group_name, brain):
    """
    Determines if group exists

    Called with initialized vectra client and name of group
    :param group_name: group name
    :param brain: initialized Vectra Client object
    :return: True if group exists, False otherwise
    """
    group_iterator = brain.get_all_groups(name=group_name)
    for item in group_iterator:
        if item.json()["count"] > 0:
            for group in item.json()["results"]:
                if group["name"] == group_name:
                    return {"name": group["name"], "id": group["id"]}
    return False


def group_exists2(group_name, group_list):
    """
    Determines if group exists in supplied group_list
    :param group_name: group name
    :param group_list: list of group dictionaries
    :return: The group dict if group exists, False otherwise
    """
    if len(group_list) > 0:
        for group in group_list:
            if group["name"].lower() == group_name.lower():
                return group
    return False


def get_all_groups(brain):
    """
    Retrieves all groups and returns a list of group dictionaries

    Called with initialized vectra client
    :param brain: initialized Vectra Client object
    :return: list of group dictionaries
    """
    group_list = list()
    group_iterator = brain.get_all_groups()
    for page in group_iterator:
        if page.json()["count"] > 0:
            for group in page.json()["results"]:
                group_list.append(group)
    return group_list


def create_group(name, subnet, brain, descr=""):
    """
    Creates group and adds supplied subnet, and description if supplied

    :param name: group name
    :param subnet: CIDR subnet string
    :param brain: initialized Vectra Client object
    :param descr: group description, optional
    """
    try:
        if bool(descr):
            brain.create_group(
                name=name, description=descr, type="ip", members=list(subnet)
            )
        else:
            brain.create_group(name=name, type="ip", members=list(subnet))
    except Exception as error:
        LOG.error("create_group exception: {}".format(str(error)))
        global ERRORS
        ERRORS.append(
            "Create group exception {}, {}, {}".format(name, list(subnet), str(error))
        )


def update_group(grp_id, subnet, brain, auth=False, descr=""):
    """
    Updates existing group with supplied subnet, and description if supplied
    :param grp_id: group ID
    :param subnet: CIDR subnet string
    :param brain: initialized Vectra Client object
    :param auth: boolean representing authoritative update (True is Append=False)
    :param descr: group description, optional
    """
    if bool(descr):
        brain.update_group(
            group_id=grp_id, description=descr, members=subnet, append=not auth
        )
    else:
        brain.update_group(group_id=grp_id, members=subnet, append=not auth)


def obtain_args():
    parser = argparse.ArgumentParser(
        description="Supplied with name of CSV input file, creates or updates IP groups "
        "with supplied subnet information.  \nCSV file format: "
        "group_name,subnet,description\n\n"
        "Subnet can be supplied in CIDR notation e.g. \n"
        "group name,10.1.1.0/24,some description\n\n"
        "or as subnet and netmask separate by a comma (,) e.g.\n"
        "group name,10.1.1.1.0,255.255.255.0,some description",
        prefix_chars="--",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="",
    )
    parser.add_argument("--brain", type=str, help="URL for the brain")
    parser.add_argument(
        "--token", type=str, help="V2 API token to access Cognito Detect"
    )
    parser.add_argument("--client_id", type=str, help="V3 API Client ID")
    parser.add_argument("--secret_key", type=str, help="V3 API Secret Key")
    parser.add_argument("--file", type=str, help="Name of csv input file")
    parser.add_argument(
        "-a",
        "--authoritative",
        action="store_true",
        help="Data contained in CSV is authoritative.  Group "
        "information will be overwritten where necessary.",
    )
    parser.add_argument(
        "-d", "--dryrun", action="store_true", help="Do dry run, no updates to Cognito"
    )
    parser.add_argument(
        "--sub_char",
        default=False,
        type=str,
        help="Override default invalid character "
        "substitution in group names and "
        "description.  Default is _\n"
        "May not be one of the following characters\n"
        "{}".format(str(INVALID_CHARS)),
    )
    parser.add_argument(
        "--verbose", default=False, action="store_true", help="Verbose logging"
    )

    return parser.parse_args()


def process_group_info(gd, g, s, d):
    """
    Supplied with a dictionary of groups, group name, subnet list, and description, returns dictionary with new
    elements added
    :param gd: Dictionary of groups
    :param g: group name
    :param s: list of subnets
    :param d: description
    :return: dictionary of groups with new elements added
    """
    if g not in gd.keys():
        gd = {**gd, **{g: {"subnets": [s], "desc": d}}}
        return gd
    else:
        gd[g]["subnets"] += [s]
        gd[g]["desc"] = d
        return gd


def process_group_info2(gd, g, s, d):
    """
    Supplied with a dictionary of groups, group name, subnet list, and description, returns dictionary with new
    elements added
    :param gd: Dictionary of groups
    :param g: group name
    :param s: list of subnets
    :param d: description
    :return: dictionary of groups with new elements added
    """
    if g.lower() not in [k.lower() for k in gd.keys()]:
        gd = {**gd, **{g: {"subnets": [s], "desc": d}}}
        return gd
    else:
        for i in gd.keys():
            if g.lower() == i.lower():
                gd[i]["subnets"] += [s]
                gd[i]["desc"] = d
        return gd


def group_missing_values(new_group, existing_group):
    """
    Supplied with a dictionary of the csv group and existing group, determines if values contained in csv group are
    missing from the existing group
    :param new_group: dictionary of group from csv
    :param existing_group: dictionary of existing group
    :return: bool, [list of missing values]
    """
    if sorted(new_group["subnets"]) == sorted(existing_group["members"]):
        # Group contents the same, update not needed, no update value
        return False, None
    elif list(set(new_group["subnets"]) - set(existing_group["members"])) and list(
        set(existing_group["members"]) - set(new_group["subnets"])
    ):
        # The group in Cognito has subnets missing and additional compared to CSV
        return 2, list(set(new_group["subnets"]) - set(existing_group["members"]))
    elif list(set(new_group["subnets"]) - set(existing_group["members"])):
        # The group in Cognito has subnets missing compared to CSV
        return 1, list(set(new_group["subnets"]) - set(existing_group["members"]))
    elif list(set(existing_group["members"]) - set(new_group["subnets"])):
        # The group in Cognito has additional subnets compared to CSV
        return -1, list(set(existing_group["members"]) - set(new_group["subnets"]))
    else:
        return False, None


def det_bom(infile):
    with open(infile, "rb") as file:
        beginning = file.read(4)
        # The order of these if-statements is important
        # otherwise UTF32 LE may be detected as UTF16 LE as well
        if beginning == b"\x00\x00\xfe\xff":
            return "utf-32-be"
        elif beginning == b"\xff\xfe\x00\x00":
            return "utf-32-le"
        elif beginning[0:3] == b"\xef\xbb\xbf":
            return "utf-8-sig"
        elif beginning[0:2] == b"\xff\xfe":
            return "utf-16-le"
        elif beginning[0:2] == b"\xfe\xff":
            return "utf-16-le"
        else:
            return "utf-8"


def main():
    """
    Supplied with valid CSV file containing 3 or 4 columns of data, iterates over rows and creates or updates groups

    Supports CSV files with following format examples with or without header row
    group 1,192.168.1.0/255.255.255.0,group1 description
    group 2,10.1.1.0/24,group2 description
    """
    args = obtain_args()
    args.brain = _format_url(args.brain)

    global ERRORS

    sub_char = args.sub_char if args.sub_char else SUB_CHAR

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if len(sys.argv) == 1:
        print("Run python3 ip_group.py -h for help.")
        sys.exit()

    file = args.file

    with open(file, newline="", encoding=det_bom(file)) as csvfile:
        # Iterate through the CSV building a dictionary of groups
        reader = csv.reader(csvfile)
        csv_groups_dict = dict()
        counter = 0
        for row in reader:
            counter += 1
            sys.stdout.write(f"\rProcessing line: {str(counter)} ")
            sys.stdout.flush()

            if len(row) < 3 or len(row) > 4:
                LOG.debug("Invalid number of columns in row, skipping")
                ERRORS.append("Invalid number of columns in row {}".format(row))
                continue
            if len(row) == 4:
                LOG.debug("Number of rows 4: {}".format(len(row)))

                subnet = ip_subnet("{}/{}".format(row[1], row[2]))
                description = sub_bad_chars(row[3], sub_char)

            elif len(row) == 3:
                LOG.debug("Number of rows 3: {}".format(len(row)))

                subnet = ip_subnet(row[1])
                description = sub_bad_chars(row[2], sub_char)

            # Replace unsupported characters and remove leading and trailing spaces
            group_name = sub_bad_chars(row[0], sub_char).strip()

            if subnet is not None:
                # group_dict = {'group1': {'subnets': [1, 2, 3], 'desc': 'group1 description'},
                # 'group2': {'subnets': [3, 4, 5], 'desc': 'group2 description'}}
                if not group_name.isprintable():
                    ERRORS.append(
                        "Non-printable characters in group name: {}".format(group_name)
                    )
                    LOG.debug(
                        "Non-printable characters in group [{}]".format(group_name)
                    )

                elif not description.isprintable():
                    ERRORS.append(
                        "Non-printable characters in group {} description: {}".format(
                            group_name, description
                        )
                    )
                    LOG.debug(
                        "Non-printable characters in description [{}]".format(
                            description
                        )
                    )

                else:
                    csv_groups_dict = process_group_info2(
                        csv_groups_dict, group_name, subnet, description
                    )
            else:
                LOG.debug("Invalid subnet, skipping")

        # Obtain list of existing groups from Cognito
        LOG.info("\nRetrieving groups from https://{}".format(args.brain))
        if "portal.vectra.ai" in args.brain:
            vc = ClientV3_latest(
                url=args.brain,
                client_id=args.client_id,
                secret_key=args.secret_key,
                verify=False,
            )
        else:
            vc = ClientV2_latest(url=args.brain, token=args.token, verify=False)
        existing_groups = get_all_groups(vc)
        LOG.info("Retrieved {} groups".format(len(existing_groups)))

        # Loop through dictionaries constructed from CSV
        groups_create = dict()
        groups_update = dict()
        groups_update_overwrite = dict()
        LOG.info("Preprocessing groups.")
        for group in csv_groups_dict.keys():
            group_exists_results = group_exists2(group, existing_groups)
            LOG.debug("Checking if group [{}] exists.".format(group))
            LOG.debug("{}".format(csv_groups_dict[group]))
            LOG.debug("Group_exists_results: {}".format(group_exists_results))
            if bool(group_exists_results):
                update_needed, update_value = group_missing_values(
                    csv_groups_dict[group], group_exists_results
                )
                if update_needed == 1:
                    # Group in Detect is missing subnets in CSV
                    LOG.debug(
                        "1:Group exists, update needed, add. id:{}, group:{}, subnets:{}".format(
                            group_exists_results["id"], group, update_value
                        )
                    )
                    groups_update = {
                        **groups_update,
                        **{
                            group: {
                                "id": group_exists_results["id"],
                                "subnets": update_value["subnets"],
                            }
                        },
                    }
                elif update_needed == -1:
                    # Group in Detect contains subnets CSV does not
                    if args.authoritative:
                        LOG.debug(
                            "-1:Group exists and has extra subnets. id:{}, group:{}, subnets:{}".format(
                                group_exists_results["id"], group, update_value
                            )
                        )
                        groups_update_overwrite = {
                            **groups_update_overwrite,
                            **{
                                group: {
                                    "id": group_exists_results["id"],
                                    "subnets": csv_groups_dict[group]["subnets"],
                                    "desc": csv_groups_dict[group]["desc"],
                                }
                            },
                        }

                elif update_needed == 2 and args.authoritative:
                    # Group in Detect contains subnets CSV does not and is missing subnets from CSV
                    LOG.debug(
                        "2a:Group exists and has extra subnets and missing. id:{}, group:{}, subnets:{}".format(
                            group_exists_results["id"], group, update_value
                        )
                    )
                    groups_update_overwrite = {
                        **groups_update_overwrite,
                        **{
                            group: {
                                "id": group_exists_results["id"],
                                "subnets": csv_groups_dict[group]["subnets"],
                                "desc": csv_groups_dict[group]["desc"],
                            }
                        },
                    }
                elif update_needed == 2 and not args.authoritative:
                    # Group in Detect contains subnets CSV does not and is missing subnets from CSV, not authoritative
                    # so update needed
                    LOG.debug(
                        "2b:Group exists and has extra subnets and missing. id:{}, group:{}, subnets:{}".format(
                            group_exists_results["id"], group, update_value
                        )
                    )
                    groups_update = {
                        **groups_update,
                        **{
                            group: {
                                "id": group_exists_results["id"],
                                "subnets": update_value,
                            }
                        },
                    }
            else:
                # Group does not exist, creating
                LOG.debug(
                    "Group does not exist. group:{}, subnets:{}, description:{}".format(
                        group,
                        csv_groups_dict[group].get("subnets"),
                        csv_groups_dict[group].get("desc"),
                    )
                )
                groups_create = {
                    **groups_create,
                    **{
                        group: {
                            "subnets": csv_groups_dict[group].get("subnets"),
                            "desc": csv_groups_dict[group].get("desc"),
                        }
                    },
                }
        LOG.debug("update:{}".format(groups_update))
        LOG.debug("create:{}".format(groups_create))
        LOG.debug("overwrite:{}".format(groups_update_overwrite))
        # Iterate over each dictionary that contains data

        if not args.dryrun:
            if groups_update:
                LOG.info("Starting update of groups.")
                for group_name in groups_update.keys():
                    LOG.info(
                        "Updating group: [{}] with id: {} to include subnets: {}".format(
                            group_name,
                            groups_update[group_name]["id"],
                            groups_update[group_name]["subnets"],
                        )
                    )
                    update_group(
                        groups_update[group_name]["id"],
                        groups_update[group_name]["subnets"],
                        vc,
                    )

            if groups_create:
                LOG.info("Starting creation of new groups.")

                for group_name in groups_create.keys():
                    LOG.info(
                        "Creating new group with name: [{}], subnets: {}, description: {}".format(
                            group_name,
                            groups_create[group_name]["subnets"],
                            groups_create[group_name]["desc"],
                        )
                    )
                    create_group(
                        group_name,
                        groups_create[group_name]["subnets"],
                        vc,
                        groups_create[group_name]["desc"],
                    )

            if groups_update_overwrite and args.authoritative:
                LOG.info("Starting update of groups, overwriting subnets from CSV.")
                for group_name in groups_update_overwrite.keys():
                    LOG.info(
                        "Overwriting group: [{}] with id: {} subnets: {}".format(
                            group_name,
                            groups_update_overwrite[group_name]["id"],
                            groups_update_overwrite[group_name]["subnets"],
                        )
                    )
                    # Pass False to mark as authoritative
                    update_group(
                        groups_update_overwrite[group_name]["id"],
                        groups_update_overwrite[group_name]["subnets"],
                        vc,
                        auth=True,
                    )

        print_errors(ERRORS)


if __name__ == "__main__":
    main()
