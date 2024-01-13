import boto3
import argparse
import os
from tqdm import tqdm

def download_vpc_flow_logs_from_s3(bucket_name, s3_key, local_file_path):
    """Downloads VPC flow logs from an S3 bucket."""
    try:
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, s3_key, local_file_path)
    except Exception as e:
        print(f"Error downloading file from S3: {e}")
        exit(1)

def read_vpc_flow_logs(file_path):
    """Reads VPC flow logs from a file."""
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        return logs
    except Exception as e:
        print(f"Error reading flow log file: {e}")
        exit(1)

def parse_vpc_flow_logs(logs):
    """Parses VPC flow logs."""
    parsed_logs = []
    for log in logs:
        parts = log.strip().split()
        if len(parts) < 7:  # Basic validation of log format
            continue
        parsed_log = {
            'src_ip': parts[3],
            'dest_ip': parts[4],
            'src_port': int(parts[5]),
            'dest_port': int(parts[6]),
            'protocol': parts[7]
        }
        parsed_logs.append(parsed_log)
    return parsed_logs

def analyze_traffic(parsed_logs):
    """Analyzes traffic patterns."""
    traffic_patterns = {}
    for log in parsed_logs:
        key = (log['dest_port'], log['protocol'])
        if key in traffic_patterns:
            traffic_patterns[key].add(log['src_ip'])
        else:
            traffic_patterns[key] = {log['src_ip']}
    return traffic_patterns

def create_security_group_rules(traffic_patterns):
    """Creates AWS security group rules based on traffic patterns."""
    ec2 = boto3.client('ec2')
    try:
        response = ec2.create_security_group(GroupName='FlowGuardGroup',
                                             Description='Security group created by FlowGuard')
        group_id = response['GroupId']

        for (port, protocol), ips in traffic_patterns.items():
            ec2.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        'IpProtocol': protocol,
                        'FromPort': port,
                        'ToPort': port,
                        'IpRanges': [{'CidrIp': f'{ip}/32'} for ip in ips]
                    }
                ]
            )
        print(f"Security group {group_id} created and rules added.")
    except Exception as e:
        print(f"Error creating security group: {e}")
        exit(1)

def main(bucket_arn):
    # Parsing bucket ARN
    parts = bucket_arn.split(':')
    bucket_name = parts[5].split('/')[0]
    s3_key = '/'.join(parts[5].split('/')[1:])
    local_file_path = '/tmp/vpc_flow_logs.txt'

    # Downloading logs
    print("Downloading VPC flow logs from S3...")
    download_vpc_flow_logs_from_s3(bucket_name, s3_key, local_file_path)

    if os.path.exists(local_file_path):
        file_size = os.path.getsize(local_file_path)
        print(f"Processing {file_size} bytes of flow logs...")
        with tqdm(total=file_size, unit='B', unit_scale=True, desc="Reading Logs") as pbar:
            flow_logs = read_vpc_flow_logs(local_file_path)
            pbar.update(file_size)

        parsed_logs = parse_vpc_flow_logs(flow_logs)
        traffic_patterns = analyze_traffic(parsed_logs)

        print("Updating security groups based on traffic patterns...")
        create_security_group_rules(traffic_patterns)
    else:
        print("Flow log file not found after download.")
        exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='FlowGuard: AWS VPC Flow Log Analyzer')
    parser.add_argument('bucket_arn', type=str, help='S3 bucket ARN containing the VPC flow logs')
    args = parser.parse_args()

    main(args.bucket_arn)
