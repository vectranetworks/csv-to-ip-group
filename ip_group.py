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
    #  Called with string that represents an IP subnet with CIDR or netmask in dotted decimal format
    #  Validates string represents valid subnet
    #  Returns string representation of subnet in CIDR format
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
    for bad_char in INVALID_CHARS:
        string = string.replace(bad_char, sub)
    return string


def group_exists(group_name, brain):
    #  Called with initialized vectra client and name of group
    #  Returns group name and ID in dictionary if group exists, False otherwise
    #  Substitute illegal characters
    group_iterator = brain.get_all_groups(name=group_name)
    for item in group_iterator:
        if item.json()['count'] > 0:
            for group in item.json()['results']:
                if group['name'] == group_name:
                    return {'name': group['name'], 'id': group['id']}
    return False


def create_group(name, subnet, brain, descr=''):
    if bool(descr):
        brain.create_group(name=name, description=descr, type='ip', members=list(subnet))
    else:
        brain.create_group(name=name, type='ip', members=list(subnet))


def update_group(grp_id, subnet, brain, descr=''):
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
    parser.add_argument('file', type=str, help='Name of csv input file')
    parser.add_argument('--sub_char', default=False, type=str, help='Override default invalid character '
                                                                    'substitution in group names and '
                                                                    'description.  Default is _\n'
                                                                    'May not be one of the following characters\n'
                                                                    '{}'.format(str(INVALID_CHARS)))
    parser.add_argument('--verbose', default=False, action='store_true', help='Verbose logging')

    return parser.parse_args()


def main():
    args = obtain_args()

    sub_char = args.sub_char if args.sub_char else SUB_CHAR

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) == 1:
        print('Run python3 ip_group.py -h for help.')
        sys.exit()

    file = args.file

    with open(file, newline='') as csvfile:
        vc = vectra.VectraClientV2_1(url='https://vhe.pieklab.local', token='7bd8169565eeadae0359ccd7021d1d30b86f32f1',
                                     verify=False)

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
                # group_obj False or {'name': 'somename', 'id':'123'}
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

