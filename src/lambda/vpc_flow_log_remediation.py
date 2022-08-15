import json
import boto3
import datetime
import botocore

##############
# Parameters #
##############

ORG_ACCOUNT = "1111111111111"

#############
# Main Code #
#############

# Lambda Handler to remediate Non-Compliant resource
def lambda_handler(event, context):
    print("Remediating VPC: "+event['VpcId'])
    config_client = get_client('config', ORG_ACCOUNT)
    account_id = get_account_id(config_client, event['VpcId'])
    fl_client = get_client('ec2',account_id)
    fl_response = fl_client.create_flow_logs(
            DeliverLogsPermissionArn='arn:aws:iam::'+account_id+':role/pk-VPCFlowLogs-to-CWL-Role',
            ResourceIds=[
                event['VpcId'],
            ],
            ResourceType='VPC',
            TrafficType='ALL',
            LogGroupName='pk-VPCFlowLogs-custom'
        )
    return fl_response

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, account_id):
    credentials = get_assume_role_credentials("arn:aws:iam::"+account_id+":role/pk-flowlog-config-remediation")
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

# Generate STS credentials
def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configRemediationExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        print(str(ex))
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# Get Account ID from Config Aggregator
def get_account_id(client, vpc_id):
    vpc_details = client.list_aggregate_discovered_resources(
        ConfigurationAggregatorName='test',
        ResourceType='AWS::EC2::VPC',
        Filters={
            'ResourceId': vpc_id,
            },
        )
    identifier = vpc_details["ResourceIdentifiers"][0]
    if identifier['ResourceId'] in vpc_id:
        print(identifier['SourceAccountId'])
        account = identifier['SourceAccountId']
        return account
    else:
        return "No account found"

    