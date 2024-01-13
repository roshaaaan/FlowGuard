# FlowGuard: AWS VPC Flow Log Analyzer

FlowGuard is a Python utility designed to enhance network security within AWS environments. It achieves this by analyzing VPC flow logs stored in an S3 bucket, identifying common traffic patterns, and automatically updating security group rules to align with these patterns.

## Features

- **Automated Download**: Fetches VPC flow logs directly from an S3 bucket.
- **Log Parsing**: Efficiently parses flow logs to extract critical traffic data.
- **Traffic Analysis**: Identifies common traffic patterns based on destination port, protocol, and source IPs.
- **Security Group Update**: Dynamically modifies AWS security group rules based on the analyzed traffic.

## Prerequisites

To use FlowGuard, ensure you have the following:

- Python 3.x installed.
- Boto3 library installed (install via `pip install boto3`).
- AWS CLI configured with necessary permissions:
  - Read access to the S3 bucket.
  - Write access to EC2 for managing security groups.

## Installation

1. Clone the FlowGuard repository or download the `flowguard.py` script.
2. Ensure that your AWS CLI is configured with the appropriate IAM roles or credentials.
3. Install required Python dependencies:
   ```bash
   pip install boto3 tqdm
   ```

## Usage
   ```bash
   python flowguard.py <s3-bucket-arn>
   ```

