import boto3
import csv
import datetime
from collections import defaultdict
from tqdm import tqdm  # For progress bars

# Function to download VPC flow logs from S3
def download_vpc_flow_logs_from_s3(s3_arn, sample_days):
    # Connect to S3 and get bucket and prefix from ARN
    s3 = boto3.client('s3')
    bucket_name, prefix = s3_arn.split(':')[4:6]

    # Get a list of files within the sample collection days limit
    now = datetime.datetime.utcnow()
    limit_date = now - datetime.timedelta(days=sample_days)
    files = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)['Contents']
    files = [file['Key'] for file in files if file['LastModified'] > limit_date]

    # Download each file and yield its contents
    for file in files:
        with tqdm(desc=f"Downloading {file}", unit="B", unit_scale=True, unit_divisor=1024) as pbar:
            obj = s3.get_object(Bucket=bucket_name, Key=file)
            for chunk in obj['Body'].iter_chunks():
                pbar.update(len(chunk))
                yield chunk.decode('utf-8')

# Function to identify egress traffic and strip columns
def identify_egress_traffic(log_data):
    reader = csv.DictReader(log_data.splitlines())
    for row in reader:
        if row['action'] == 'ACCEPT' and row['flow-direction'] == 'egress':
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

# Main program
def main():
    # Get S3 ARN and sample days as command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Analyze VPC flow logs from S3")
    parser.add_argument("s3_arn", help="The S3 ARN for VPC flow logs")
    parser.add_argument("sample_days", type=int, help="The number of days for sample collection")
    args = parser.parse_args()

    traffic_pattern = defaultdict(lambda: defaultdict(set))  # Define traffic_pattern here

    for log_data in download_vpc_flow_logs_from_s3(s3_arn, sample_days):
        for log_entry in identify_egress_traffic(log_data):
            for key, value in log_entry.items():
                if key in ['srcaddr', 'dstaddr', 'dstport', 'protocol']:
                    traffic_pattern[log_entry['srcaddr']][key].add(value)
                    
if __name__ == "__main__":
    main()

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
        values['protocol'],
        values.get('vpc-id', ''),
        values.get('subnet-id', ''),
        values.get('instance-id', ''),  # Corrected line
        values.get('region', '')
    ))

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
            values['protocol'],
            values.get('vpc-id', ''),
            values.get('subnet-id', ''),
            values.get('instance-id', ''),
            values.get('region', '')
        ))