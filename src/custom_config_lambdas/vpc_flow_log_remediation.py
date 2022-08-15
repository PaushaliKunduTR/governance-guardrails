import json
import boto3
import datetime
import botocore

ORG_ACCOUNT = "1111111111111"
PARAMETER_VALUE = "non_compliant_vpcs_by_account"

def lambda_handler(event, context):
    print("Remediating VPC: "+event['VpcId'])
    response_list = []
    ssm_client = get_client('ssm', ORG_ACCOUNT)
    non_compliant_data = get_params(ssm_client, PARAMETER_VALUE)
    for vpc_pair in non_compliant_data:
        print("loop")
        print(vpc_pair)
        vpc_pair = vpc_pair.split(" : ")
        vpc_id = vpc_pair[0]
        vpc_id = vpc_id.lstrip("'")
        print(vpc_id)
        account_id = vpc_pair[1]
        account_id = account_id.rstrip("'")
        print(account_id)
        if event['VpcId'] in vpc_id:
            print("creating flow logs... ")
            fl_client = get_client('ec2',account_id)
            # response = create_flow_logs(fl_client, vpc_id, account_id)
            fl_response = fl_client.create_flow_logs(
                    DeliverLogsPermissionArn='arn:aws:iam::'+account_id+':role/pk-VPCFlowLogs-to-CWL-Role',
                    ResourceIds=[
                        event['VpcId'],
                    ],
                    ResourceType='VPC',
                    TrafficType='ALL',
                    LogGroupName='pk-VPCFlowLogs-custom'
                )
            print(fl_response)
            response_list.append(fl_response)
            continue
    return response_list

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

def get_params(client, param):
    response = client.get_parameter(
            Name=param
        )
    parameter = response["Parameter"]
    value = parameter["Value"]
    value = value.lstrip("[").rstrip("]")
    vpc_dict = value.split(',')
    return vpc_dict
    