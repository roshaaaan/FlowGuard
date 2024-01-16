import boto3
import csv
import datetime
import pytz  # Import the pytz library
import re  # Import regex module
from collections import defaultdict
from tqdm import tqdm  # For progress bars

# Function to download VPC flow logs from S3
def download_vpc_flow_logs_from_s3(sample_days):
    s3 = boto3.client('s3')
    match = re.search(r'arn:aws:s3:::(?P<bucket_name>[^/]+)(?:/(?P<prefix>.*))?', args.s3_arn)
    if match:
        bucket_name = match.group('bucket_name')
        initial_prefix = match.group('prefix') or ''  # Default to empty string if no prefix
    else:
        raise ValueError("Invalid S3 ARN format")

    now = datetime.datetime.now(pytz.utc)
    limit_date = now - datetime.timedelta(days=sample_days)

    def list_files(bucket, prefix):
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                if obj['LastModified'] > limit_date:
                    yield obj['Key']

    for file_key in list_files(bucket_name, initial_prefix):
        with tqdm(desc=f"Downloading {file_key}", unit="B", unit_scale=True, unit_divisor=1024) as pbar:
            obj = s3.get_object(Bucket=bucket_name, Key=file_key)
            for chunk in obj['Body'].iter_chunks():
                pbar.update(len(chunk))
                yield chunk.decode('utf-8')

# Function to identify egress traffic and strip columns
def identify_egress_traffic(log_data):
    reader = csv.DictReader(log_data.splitlines())
    found_egress_traffic = False  # Debugging flag
    for row in reader:
        print("Debug - Processing row:", row)  # Debugging line
        if row['action'] == 'ACCEPT' and row['flow-direction'] == 'egress':
            found_egress_traffic = True
            yield {
                'srcaddr': row['srcaddr'],
                'dstaddr': row['dstaddr'],
                'dstport': row['dstport'],
                'protocol': row['protocol'],
                'vpc-id': row['vpc-id'],
                'subnet-id': row['subnet-id'],
                'instance-id': row['instance-id'],
                'region': row['region']
            }
    if not found_egress_traffic:
        print("Debug - No egress traffic found in this chunk.")

# Main program
# Main program
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Analyze VPC flow logs from S3")
    parser.add_argument("s3_arn", help="The S3 ARN for VPC flow logs")
    parser.add_argument("sample_days", type=int, help="The number of days for sample collection")
    global args  # Make args global for access within functions
    args = parser.parse_args()

    traffic_pattern = defaultdict(lambda: defaultdict(set))

    for log_data in download_vpc_flow_logs_from_s3(args.sample_days):
        for log_entry in identify_egress_traffic(log_data):
            for key, value in log_entry.items():
                if key in ['srcaddr', 'dstaddr', 'dstport', 'protocol']:
                    traffic_pattern[log_entry['srcaddr']][key].add(value)

    # Print the traffic pattern in a table format
    print("\nTraffic Pattern:")
    print("-" * 50)
    print("{:<15} {:<15} {:<10} {:<8} {:<15} {:<15} {:<15} {:<15}".format(
        "srcaddr", "dstaddr(s)", "dstport(s)", "protocol", "vpc-id", "subnet-id", "instance-id", "region"))
    print("-" * 50)
    for srcaddr, values in traffic_pattern.items():
        print("{:<15} {:<15} {:<10} {:<8} {:<15} {:<15} {:<15} {:<15}".format(
            srcaddr,
            ','.join(values['dstaddr']),
            ','.join(values['dstport']),
            ','.join(values['protocol']),  # Fix to join protocol values
            values.get('vpc-id', ''),
            values.get('subnet-id', ''),
            values.get('instance-id', ''),
            values.get('region', '')))

    # Write the traffic pattern to a text file
    with open("traffic_pattern.txt", "w") as file:
        file.write("\nTraffic Pattern:\n")
        file.write("-" * 50 + "\n")
        file.write("{:<15} {:<15} {:<10} {:<8} {:<15} {:<15} {:<15} {:<15}\n".format(
            "srcaddr", "dstaddr(s)", "dstport(s)", "protocol", "vpc-id", "subnet-id", "instance-id", "region"))
        file.write("-" * 50 + "\n")
        for srcaddr, values in traffic_pattern.items():
            file.write("{:<15} {:<15} {:<10} {:<8} {:<15} {:<15} {:<15} {:<15}\n".format(
                srcaddr,
                ','.join(values['dstaddr']),
                ','.join(values['dstport']),
                ','.join(values['protocol']),
                values.get('vpc-id', ''),
                values.get('subnet-id', ''),
                values.get('instance-id', ''),
                values.get('region', '')))

if __name__ == "__main__":
    main()
