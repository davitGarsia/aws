import argparse
import boto3
import ipaddress
import socket
from os import getenv

ec2_client = boto3.client(
    "ec2",
    aws_access_key_id=getenv("aws_access_key_id"),
    aws_secret_access_key=getenv("aws_secret_access_key"),
    aws_session_token=getenv("aws_session_token"),
    region_name=getenv("aws_region_name")
)

rds_client = boto3.client(
    "rds",
    aws_access_key_id=getenv("aws_access_key_id"),
    aws_secret_access_key=getenv("aws_secret_access_key"),
    aws_session_token=getenv("aws_session_token"),
    region_name=getenv("aws_region_name")
)

dynamodb_client = boto3.client(
    "dynamodb",
    aws_access_key_id=getenv("aws_access_key_id"),
    aws_secret_access_key=getenv("aws_secret_access_key"),
    aws_session_token=getenv("aws_session_token"),
    region_name=getenv("aws_region_name")
)

def validate_cidr(cidr):
    try:
        ipaddress.IPv4Network(cidr)
        return cidr
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid CIDR block: {cidr}")

def create_vpc(ec2, cidr_block, vpc_name):
    vpc = ec2.create_vpc(CidrBlock=cidr_block)
    ec2.create_tags(Resources=[vpc['Vpc']['VpcId']], Tags=[{"Key": "Name", "Value": vpc_name}])
    waiter = ec2.get_waiter('vpc_available')
    waiter.wait(VpcIds=[vpc['Vpc']['VpcId']])
    return vpc['Vpc']

def create_igw(ec2, vpc_id):
    igw = ec2.create_internet_gateway()
    ec2.attach_internet_gateway(InternetGatewayId=igw['InternetGateway']['InternetGatewayId'], VpcId=vpc_id)
    return igw['InternetGateway']

def create_subnet(ec2, vpc_id, cidr_block, subnet_name, is_public):
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr_block)
    ec2.create_tags(Resources=[subnet['SubnetId']], Tags=[{"Key": "Name", "Value": subnet_name}])
    if is_public:
        ec2.modify_subnet_attribute(SubnetId=subnet['SubnetId'], MapPublicIpOnLaunch={"Value": True})
    return subnet['Subnet']

def create_route_table(ec2, vpc_id, igw_id, public_subnet_id):
    route_table = ec2.create_route_table(VpcId=vpc_id)
    ec2.create_route(
        RouteTableId=route_table['RouteTableId'],
        DestinationCidrBlock="0.0.0.0/0",
        GatewayId=igw_id
    )
    ec2.associate_route_table(RouteTableId=route_table['RouteTableId'], SubnetId=public_subnet_id)
    return route_table['RouteTable']

def create_security_group(ec2, vpc_id, sg_name, description, my_ip):
    response = ec2.create_security_group(
        GroupName=sg_name,
        Description=description,
        VpcId=vpc_id
    )
    security_group_id = response['GroupId']

    ec2.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': f'{my_ip}/32'}]
            }
        ]
    )
    return security_group_id

def create_key_pair(ec2, key_name):
    key_pair = ec2.create_key_pair(KeyName=key_name)
    with open(f"{key_name}.pem", "w") as file:
        file.write(key_pair['KeyMaterial'])
    return key_pair['KeyName']

def launch_ec2_instance(ec2, ami_id, instance_type, key_name, security_group_id, subnet_id):
    instances = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        KeyName=key_name,
        SecurityGroupIds=[security_group_id],
        SubnetId=subnet_id,
        MinCount=1,
        MaxCount=1
    )
    instance_id = instances['Instances'][0]['InstanceId']
    ec2.get_waiter('instance_running').wait(InstanceIds=[instance_id])
    instance_description = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = instance_description['Reservations'][0]['Instances'][0]['PublicIpAddress']
    return instance_id, public_ip

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def create_rds_instance(rds):
    response = rds.create_db_instance(
        DBName='mysql_instance_davit',
        DBInstanceIdentifier='demo-mysql',
        AllocatedStorage=60,
        DBInstanceClass='db.t4g.micro',
        Engine='mysql',
        MasterUsername=getenv("rds_username"),
        MasterUserPassword=getenv("rds_password"),
        BackupRetentionPeriod=7,
        Port=3306,
        MultiAZ=False,
        EngineVersion='13.5',
        AutoMinorVersionUpgrade=True,
        PubliclyAccessible=True,
        Tags=[
            {
                'Key': 'Name',
                'Value': 'First RDS'
            },
        ],
        StorageType='gp2',
        EnablePerformanceInsights=True,
        PerformanceInsightsRetentionPeriod=7,
        DeletionProtection=False,
    )
    _id = response.get("DBInstance").get("DBInstanceIdentifier")
    print(f"Instance {_id} was created")

    return response

def print_connection_params(rds, identifier):
  response = rds.describe_db_instances(DBInstanceIdentifier=identifier)
  instance = response.get("DBInstances")[0]
  endpoint = instance.get("Endpoint")
  host = endpoint.get("Address")
  port = endpoint.get("Port")
  username = instance.get(getenv("rds_username")),
  db_name = instance.get("mysql_instance_davit")
  print("DB Host:", host)
  print("DB port:", port)
  print("DB user:", username)
  print("DB database:", db_name)

def update_security_group_for_rds(ec2, security_group_id):
    ec2.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 3306,
                'ToPort': 3306,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )

def increase_rds_memory(rds, db_instance_identifier):
    response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
    db_instance_class = response['DBInstances'][0]['DBInstanceClass']
    current_allocated_storage = response['DBInstances'][0]['AllocatedStorage']
    new_allocated_storage = int(current_allocated_storage * 1.25)

    rds.modify_db_instance(
        DBInstanceIdentifier=db_instance_identifier,
        AllocatedStorage=new_allocated_storage,
        ApplyImmediately=True
    )
    print(f"RDS instance {db_instance_identifier} memory increased by 25% to {new_allocated_storage} GB")

def list_dynamodb_tables(dynamodb):
    response = dynamodb.list_tables()
    tables = response.get('TableNames', [])
    print("DynamoDB Tables:")
    for table in tables:
        print(f" - {table}")

def create_rds_snapshot(rds, db_instance_identifier):
    snapshot_identifier = f"{db_instance_identifier}-snapshot"
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snapshot_identifier,
        DBInstanceIdentifier=db_instance_identifier
    )
    print(f"Created snapshot {snapshot_identifier} for RDS instance {db_instance_identifier}")

def main():
    parser = argparse.ArgumentParser(description="Create an AWS VPC with subnets, an internet gateway, launch an EC2 instance, and create an RDS instance")
    parser.add_argument("--vpc-cidr", type=validate_cidr, required=True, help="CIDR block for the VPC")
    parser.add_argument("--vpc-name", type=str, required=True, help="Name of the VPC")
    parser.add_argument("--subnet-cidr", type=validate_cidr, required=True, help="CIDR block for the Subnet")
    parser.add_argument("--subnet-name", type=str, required=True, help="Name of the Subnet")
    parser.add_argument("--ami-id", type=str, required=True, help="AMI ID for the EC2 instance")
    parser.add_argument("--key-name", type=str, required=True, help="Key pair name for the EC2 instance")
    parser.add_argument("--region", type=str, default="us-east-1", help="AWS region")
    parser.add_argument("--existing-sg-id", type=str, required=True, help="Existing Security Group ID to associate with RDS")

    args = parser.parse_args()

    vpc = create_vpc(ec2_client, args.vpc_cidr, args.vpc_name)
    print(f"Created VPC {vpc['VpcId']} with CIDR {args.vpc_cidr}")

    igw = create_igw(ec2_client, vpc['VpcId'])
    print(f"Created and attached Internet Gateway {igw['InternetGatewayId']} to VPC {vpc['VpcId']}")

    subnet = create_subnet(ec2_client, vpc['VpcId'], args.subnet_cidr, args.subnet_name, is_public=True)
    print(f"Created Public Subnet {subnet['SubnetId']} with CIDR {args.subnet_cidr}")

    create_route_table(ec2_client, vpc['VpcId'], igw['InternetGatewayId'], subnet['SubnetId'])
    print(f"Created Route Table for Public Subnet {subnet['SubnetId']}")

    my_ip = get_my_ip()
    security_group_id = create_security_group(ec2_client, vpc['VpcId'], "my-sg", "Security group for my instance", my_ip)
    print(f"Created Security Group {security_group_id} with HTTP and SSH access")

    key_name = create_key_pair(ec2_client, args.key_name)
    print(f"Created Key Pair {key_name}")

    instance_id, public_ip = launch_ec2_instance(
        ec2_client, args.ami_id, "t2.micro", key_name, security_group_id, subnet['SubnetId']
    )
    print(f"Launched EC2 Instance {instance_id} with public IP {public_ip}")

    create_rds_instance(rds_client)
    print(f"Created RDS Instance demo-mysql")

    update_security_group_for_rds(ec2_client, args.existing_sg_id)
    print(f"Updated Security Group {args.existing_sg_id} to allow access to RDS instance from any IP address")

    increase_rds_memory(rds_client, 'demo-mysql')

    list_dynamodb_tables(dynamodb_client)

    create_rds_snapshot(rds_client, 'demo-mysql')

if __name__ == "__main__":
    main()
