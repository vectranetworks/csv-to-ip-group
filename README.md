# ip_group

ip_group.py is a python script that creates or updates IP Groups in Cognito Detect via Detect's API from a CSV formatted
list.

## Prerequisites

Python3, requests, and Vectra API Tools (vat) modules.  
Required modules will be installed when following the procedure outlined.  

A Cognito Detect API token is required and can be generated by going to **My Profile** and Generating an API token. 

A CSV formatted file containing the group names, IP subnets, and descriptions to be created or updated.

## Setup
Manually clone or download using git, install requirements with pip3:
```
git clone https://github.com/vectranetworks/csv-to-ip-group.git
pip3 install -r requirements.txt
```


## CSV file format
The CSV file can include a CSV header row.  
The CSV file can contain either 3 or 4 columns of data, and can include a description.  
3-column format (subnet in CIDR notation) example:
```
group 1,10.1.1.0/24, group 1 description
group 1,10.1.2.0/24,
group 2,10.2.0.0/16, group 2 description
```
4-column format (subnet in netmask notation) example:
```
group 1,10.1.1.0,255.255.255.0, group 1 description
group 1,10.1.2.0,255.255.255.0,
group 2,10.2.0.0,255.255.0.0, group 2 description
```
## Notes
Subnets that have host bits set will automatically have the host bits removed.

Group names and description do not support the following characters which will automatically be replaced by the '_' 
character.

```'~', '#', '$', '^', '+', '=', '<', '>', '?', ';'```

An alternate substitution character can be specified with the **--sub_char** cli flag.


## Running

When ran, the script needs to be supplied one or more parameters.  Example:


```
python3 ip_group.py <brain IP/hostname> <cognito_token> subnet_data.csv
```
 
 
## Help Output

python3 ip_group.py -h  
usage: ip_group.py [-h] [--sub_char SUB_CHAR] [--verbose] brain token file  

Supplied with name of CSV input file, creates or updates IP groups with supplied subnet information.  
CSV file format: group_name,subnet,description

Subnet can be supplied in CIDR notation e.g.  
group name,10.1.1.0/24,some description  

or as subnet and netmask separate by a comma (,) e.g.  
group name,10.1.1.1.0,255.255.255.0,some description

positional arguments:  
  brain                Hostname or IP of Congito Detect brain  
  token                API token to access Cognito Detect  
  file                 Name of csv input file  

optional arguments:  
  -h, --help           show this help message and exit  
  --sub_char SUB_CHAR  Override default invalid character substitution in group names and description.  Default is _  
                       May not be one of the following characters  
                       ['~', '#', '$', '^', '+', '=', '<', '>', '?', ';']  
  --verbose            Verbose logging  


## Authors

* **Matt Pieklik** - *Initial work*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details