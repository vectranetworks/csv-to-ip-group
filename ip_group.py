import csv
import ipaddress
import logging.handlers
import sys
import argparse


try:
    import vat.vectra as vectra
    import requests
except Exception as error:
    print('\nMissing import requirements: {}\n'.format(str(error)))
    sys.exit(0)

LOG = logging.getLogger(__name__)

INVALID_CHARS = ['~', '#', '$', '^', '+', '=', '<', '>', '?', ';']
SUB_CHAR = '_'

# Suppress Detect certificate warning
requests.packages.urllib3.disable_warnings()


def ip_subnet(subnet_string):
    """
    Called with string that represents an IP subnet with CIDR or netmask in dotted decimal format

    Validates string represents valid subnet and removes host bits
    Returns string representation of subnet in CIDR format
    :param subnet_string: string representing subnet in CIDR w.x.y.z/n or netmask w.x.y.z/aa.bb.cc.dd format
    :return: returns string representation of subnet in CIDR format
    """
    try:
        ipaddress.IPv4Network(subnet_string)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        LOG.info('Subnet {} format error, {}'.format(subnet_string, error))
        return
    except ValueError as error:
        LOG.info('{}, removing host bits'.format(error))
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
        if item.json()['count'] > 0:
            for group in item.json()['results']:
                if group['name'] == group_name:
                    return {'name': group['name'], 'id': group['id']}
    return False


def create_group(name, subnet, brain, descr=''):
    """
    Creates group and adds supplied subnet, and description if supplied

    :param name: group name
    :param subnet: CIDR subnet string
    :param brain: initialized Vectra Client object
    :param descr: group description, optional
    """
    if bool(descr):
        brain.create_group(name=name, description=descr, type='ip', members=list(subnet))
    else:
        brain.create_group(name=name, type='ip', members=list(subnet))


def update_group(grp_id, subnet, brain, descr=''):
    """
    Updates existing group with supplied subnet, and description if supplied

    :param grp_id: group ID
    :param subnet: CIDR subnet string
    :param brain: initialized Vectra Client object
    :param descr: group description, optional
    """
    if bool(descr):
        brain.update_group(group_id=grp_id, description=descr, members=subnet, append=True)
    else:
        brain.update_group(group_id=grp_id, members=subnet, append=True)


def obtain_args():
    parser = argparse.ArgumentParser(description='Supplied with name of CSV input file, creates or updates IP groups '
                                                 'with supplied subnet information.  \nCSV file format: '
                                                 'group_name,subnet,description\n\n'
                                                 'Subnet can be supplied in CIDR notation e.g. \n'
                                                 'group name,10.1.1.0/24,some description\n\n'
                                                 'or as subnet and netmask separate by a comma (,) e.g.\n'
                                                 'group name,10.1.1.1.0,255.255.255.0,some description',
                                     prefix_chars='--', formatter_class=argparse.RawTextHelpFormatter,
                                     epilog='')
    parser.add_argument('brain', type=str, help='Hostname or IP of Congito Detect brain')
    parser.add_argument('token', type=str, help='API token to access Cognito Detect')
    parser.add_argument('file', type=str, help='Name of csv input file')
    parser.add_argument('--sub_char', default=False, type=str, help='Override default invalid character '
                                                                    'substitution in group names and '
                                                                    'description.  Default is _\n'
                                                                    'May not be one of the following characters\n'
                                                                    '{}'.format(str(INVALID_CHARS)))
    parser.add_argument('--verbose', default=False, action='store_true', help='Verbose logging')

    return parser.parse_args()


def main():
    """
    Supplied with valid CSV file containing 3 or 4 columns of data, iterates over rows and creates or updates groups

    Supports CSV files with following format examples with or without header row
    group 1,192.168.1.0/255.255.255.0,group1 description
    group 2,10.1.1.0/24,group2 description
    """
    args = obtain_args()

    sub_char = args.sub_char if args.sub_char else SUB_CHAR

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) == 1:
        print('Run python3 ip_group.py -h for help.')
        sys.exit()

    file = args.file

    with open(file, newline='') as csvfile:
        vc = vectra.VectraClientV2_1(url='https://' + args.brain, token=args.token, verify=False)

        reader = csv.reader(csvfile)

        for row in reader:
            if len(row) < 3 or len(row) > 4:
                LOG.info('Invalid number of columns in row, skipping')
                continue
            if len(row) == 4:
                LOG.debug('Number of rows 4: {}'.format(len(row)))

                subnet = ip_subnet('{}/{}'.format(row[1], row[2]))
                description = sub_bad_chars(row[3], sub_char)

            elif len(row) == 3:
                LOG.debug('Number of rows 3: {}'.format(len(row)))

                subnet = ip_subnet(row[1])
                description = sub_bad_chars(row[2], sub_char)

            group_name = sub_bad_chars(row[0], sub_char)

            if subnet is not None:
                """group_obj False or {'name': 'somename', 'id':'123'}"""
                group_obj = group_exists(group_name, vc)

                if not group_obj:
                    # Group does not exist, creating
                    LOG.info('Group does not exist, creating. group:{}, subnet:{}, description:{}'.format(
                        group_name, subnet, description))
                    create_group(group_name, [str(subnet)], vc, description)
                else:
                    LOG.info('Group exists, updating. group:{}, subnet:{}, description:{}'.format(
                        group_name, subnet, description))
                    update_group(group_obj['id'], [str(subnet)], vc, description)
            else:
                LOG.info('Invalid subnet, skipping')


if __name__ == '__main__':
    main()

