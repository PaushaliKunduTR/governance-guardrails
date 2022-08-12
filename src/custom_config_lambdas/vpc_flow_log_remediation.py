import json
import boto3
import datetime
import botocore

def lambda_handler(event, context):
    print(event)
    vpc_id = event['VpcId']
    account_id = event['AccountId']
    execution_id = event['ExecutionId']
    # fl_client = boto3.client('ec2')
    fl_client = get_client('ec2',account_id)
    response = create_flow_logs(fl_client, vpc_id, account_id)
    return response

def get_client(service, account_id):
    credentials = get_assume_role_credentials("arn:aws:iam::"+account_id+":role/pk-flowlog-config-remediation")
    # credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

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
 
def create_flow_logs(client, vpc_id, account_id):
    fl_response = client.create_flow_logs(
        DeliverLogsPermissionArn='arn:aws:iam::'+account_id+':role/pk-VPCFlowLogs-to-CWL-Role',
        ResourceIds=[
            vpc_id,
        ],
        ResourceType='VPC',
        TrafficType='ALL',
        LogGroupName='pk-VPCFlowLogs-custom'
    )
    return fl_response

    