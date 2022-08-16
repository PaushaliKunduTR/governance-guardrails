
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
'''
#####################################
##           Gherkin               ##
#####################################

Rule Name:
    vpc-flow-logs-enabled

Description: 
    Check whether VPCs have Flow Logs enabled.

Trigger: 
    Periodic

Reports on: 
    AWS::EC2::VPC

Rule Parameters:

+-------------------------+----------------+--------------------------------------------------------------------------------------------+
|   Parameter Name        | Type           |                                          Description                                       |
+-------------------------+----------------+--------------------------------------------------------------------------------------------+
| IncludeMemberAccounts   | Optional       | This parameter can be used to check if member accounts will be included, the VPCs of member|
|                         |                | accounts will be evaluated. Accepted Values are True & False                               |
+-------------------------+----------------+--------------------------------------------------------------------------------------------+


Feature:
  In order to: monitor traffic for a VPC
           As: a Security Officer
       I want: to ensure that all VPCs have Flow logs associated as per requirements.

Scenarios:

  Scenario 1:
    Given: The parameter is not valid
     Then: Raise Exception

  Scenario 2:
    Given: The parameter IncludeMemberAccounts is configured to False
      And: The VPC in the main account has flow logs associated
     Then: Return COMPLIANT

  Scenario 3:
    Given: The parameter IncludeMemberAccounts is not configured
      And: The VPC in main account does not have any Flow Logs associated
     Then: Return NON_COMPLIANT

  Scenario 4:
    Given: The parameter IncludeMemberAccounts is configured to True
      And: The VPC of one or more member account has no Flow Logs associated
     Then: Return NON_COMPLIANT

  Scenario 5:
    Given: The parameter IncludeMemberAccounts is configured to True
      And: The VPC of every member account has Flow Logs associated
     Then: Return COMPLIANT

'''

import json
import datetime
import boto3
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::VPC'

# List of the parameter allowed for the Rule
ALLOWED_PARAMETER_NAMES = ['IncludeMemberAccounts']

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = True

# List of member accounts
MEMBER_ACCOUNTS = ["22222222222", "1111111111111","33333333333","44444444444"]
ORG_ACCOUNT = "1111111111111"
PARAMETER_VALUE = "non_compliant_vpcs_by_account"
#############
# Main Code #
#############

def evaluate_compliance(event, rule_parameters):
    """Form the evaluation(s) to be return to Config Rules

    Return either:
    None -- when no result needs to be displayed
    a string -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    a dictionary -- the evaluation dictionary, usually built by build_evaluation_from_config_item()
    a list of dictionary -- a list of evaluation dictionary , usually built by build_evaluation()

    Keyword arguments:
    event -- the event variable given in the lambda handler
    configuration_item -- the configurationItem dictionary in the invokingEvent
    valid_rule_parameters -- the output of the evaluate_parameters() representing validated parameters of the Config Rule

    Advanced Notes:
    1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status, the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
    2 -- if a None or a list of dictionary is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
    3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
    """

    evaluations = []
    vpc_id_list = []
    all_vpc_ids = []
    vpc_flow_log_list = []
    account_list = []
    all_accounts = []
    eval_f_accounts = []
    eval_s_accounts = []
    non_compliant_vpcs = []

    if rule_parameters['IncludeMemberAccounts'] in "True":
        for member in MEMBER_ACCOUNTS:
            print("member: "+member)
            ec2_client, account = get_client('ec2', member)
            vpc_id_list, account = get_all_vpc_id(ec2_client, member)
            print(vpc_id_list)
            all_vpc_ids.extend(vpc_id_list)
            all_accounts.append(member)
            print(all_vpc_ids)
            all_flow_logs, account = get_all_flow_logs(ec2_client, all_vpc_ids, all_accounts)
            vpc_flow_log_list.extend(all_flow_logs)
            print(all_accounts)
            print(vpc_flow_log_list)
    else:
        ec2_client, account = get_client('ec2', "1111111111111")
        vpc_id_list, account = get_all_vpc_id(ec2_client, account)
        vpc_flow_log_list, account = get_all_flow_logs(ec2_client, vpc_id_list, account)
        print(vpc_flow_log_list)
     
    vpc_id_list = all_vpc_ids.copy()
    account_list = all_accounts.copy()

    for vpc_id, account in zip(vpc_id_list, account_list):
        print("evaluate compliance for: " + account)
        flow_log_exist = False

        for vpc_flow_log in vpc_flow_log_list:
            if vpc_flow_log['ResourceId'] != vpc_id:
                continue    
            flow_log_exist = True
            

        if not flow_log_exist:
            evaluations.append(build_evaluation(vpc_id, 'NON_COMPLIANT', event,  annotation='No flow log has been configured.'))
            eval_f_accounts.append(account)
            non_compliant_vpcs.append(vpc_id)
            continue

        evaluations.append(build_evaluation(vpc_id, 'COMPLIANT', event, annotation=''))
        eval_s_accounts.append(account)
    
    ssm_client, account = get_client('ssm', ORG_ACCOUNT)
    vpc_params = store_in_ssm(ssm_client, eval_f_accounts, non_compliant_vpcs)
    print(vpc_params)

    return evaluations, eval_f_accounts, eval_s_accounts, vpc_params

# Store non-compliant vpc info in parameter store
def store_in_ssm(ssm_client, nc_accounts, nc_vpc_ids):
    param_list = []
    for vpc, account in zip(nc_vpc_ids, nc_accounts):
        param_list.append(vpc+" : "+account)
    print(param_list)
    non_compliant_vpcs = ssm_client.put_parameter(
            Name=PARAMETER_VALUE,
            Description='Stores non-compliant vpcs across accounts that do not have flow logs enabled',
            Value=str(param_list),
            Overwrite=True,
            Type='StringList',
            Tier='Standard',
            DataType='text')
    response = ssm_client.get_parameter(
            Name=PARAMETER_VALUE
        )
    parameter = response["Parameter"]
    value = parameter["Value"]
    value = value.lstrip("[").rstrip("]")
    vpc_dict = value.split(',')

    print(vpc_dict)
    for vpc_pair in vpc_dict:
        print(vpc_pair)
    return non_compliant_vpcs


def get_all_flow_logs(ec2_client, vpc_list, account):
    flow_logs = ec2_client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': vpc_list}], MaxResults=1000)
    all_flow_logs = []
    while True:
        all_flow_logs += flow_logs['FlowLogs']
        if "NextToken" in flow_logs:
                flow_logs = ec2_client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': vpc_list}], NextToken=flow_logs["NextToken"], MaxResults=1000)
        else:
            break
    return all_flow_logs, account

def get_all_vpc_id(ec2_client, account):
    vpc_list = ec2_client.describe_vpcs()['Vpcs']
    vpc_id_list = []

    for vpc in vpc_list:
        vpc_id_list.append(vpc['VpcId'])

    return vpc_id_list, account    

def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.

    Return:
    anything suitable for the evaluate_compliance()

    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """

    for key in rule_parameters:
        if key not in ALLOWED_PARAMETER_NAMES:
            raise ValueError('The parameter ' + key + ' is not a valid parameter key.')

    validated_rule_parameters = {}

    validated_rule_parameters['IncludeMemberAccounts'] = 'False'
    if 'IncludeMemberAccounts' in rule_parameters:
        if rule_parameters['IncludeMemberAccounts'] not in ['True', 'False']:
            raise ValueError('The parameter "IncludeMemberAccounts" must be True or False.')  
        validated_rule_parameters['IncludeMemberAccounts'] = rule_parameters['IncludeMemberAccounts']

    return validated_rule_parameters

####################
# Helper Functions #
####################

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):
    """Return an error dictionary when the evaluate_parameters() raises a ValueError.

    Keyword arguments:
    ex -- Exception text
    """
    return  build_error_response(internalErrorMessage="Parameter value is invalid",
                                 internalErrorDetails="An ValueError was raised during the validation of the Parameter value",
                                 customerErrorCode="InvalidParameterValueException",
                                 customerErrorMessage=str(ex))

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, account):
    """Return the service boto client. It should be used instead of directly calling the client.

    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    # print("RoleArn is: "+event["executionRoleArn"])
    print("In account: "+account)
    credentials = get_assume_role_credentials("arn:aws:iam::"+account+":role/pk-custom-config-lambda-role")
    # credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       ), account

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.

    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    account -- account id of the 
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc

####################
# Boilerplate Code #
####################

# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'ScheduledNotification'

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, 'invokingEvent')
    if is_scheduled_notification(invokingEvent['messageType']):
        return None
    return check_defined(invokingEvent['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    try:
        check_defined(configurationItem, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configurationItem['configurationItemStatus']
    eventLeftScope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope

def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
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

# This removes older evaluation (usually useful for periodic rule not reporting on AWS::::Account).
def clean_up_old_evaluations(latest_evaluations, event):

    cleaned_evaluations = []

    old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=event['configRuleName'],
        ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
        Limit=100)

    old_eval_list = []

    while True:
        for old_result in old_eval['EvaluationResults']:
            old_eval_list.append(old_result)
        if 'NextToken' in old_eval:
            next_token = old_eval['NextToken']
            old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
                ConfigRuleName=event['configRuleName'],
                ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
                Limit=100,
                NextToken=next_token)
        else:
            break

    for old_eval in old_eval_list:
        old_resource_id = old_eval['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        newer_founded = False
        for latest_eval in latest_evaluations:
            if old_resource_id == latest_eval['ComplianceResourceId']:
                newer_founded = True
        if not newer_founded:
            cleaned_evaluations.append(build_evaluation(old_resource_id, "NOT_APPLICABLE", event))

    return cleaned_evaluations + latest_evaluations

# This decorates the lambda_handler in rule_code with the actual PutEvaluation call
def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT

    non_c_account = []
    print(event)
    print("event")
    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    print(invoking_event)
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])
    try:  
        valid_rule_parameters = evaluate_parameters(rule_parameters)
        print(valid_rule_parameters)
    except ValueError as ex:
        return build_parameters_value_error_response(ex)

    try:
        AWS_CONFIG_CLIENT, account = get_client('config', ORG_ACCOUNT)
        if invoking_event['messageType'] in ['ScheduledNotification']:
            configuration_item = get_configuration_item(invoking_event)
            if is_applicable(configuration_item, event):
                compliance_result, non_c_account, c_account, param_store = evaluate_compliance(event, valid_rule_parameters)
                print(compliance_result)
            else:
                compliance_result = "NOT_APPLICABLE"
        else:
            return build_internal_error_response('Unexpected message type', str(invoking_event))
    except botocore.exceptions.ClientError as ex:
        if is_internal_error(ex):
            return build_internal_error_response("Unexpected error while completing API request", str(ex))
        return build_error_response("Customer error while making API request", str(ex), ex.response['Error']['Code'], ex.response['Error']['Message'])
    except ValueError as ex:
        return build_internal_error_response(str(ex), str(ex))

    evaluations = []
    latest_evaluations = []

    if not compliance_result:
        latest_evaluations.append(build_evaluation(event['accountId'], "NOT_APPLICABLE", event, resource_type='AWS::::Account')) ######
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, list):
        for evaluation in compliance_result:
            missing_fields = False
            for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
                if field not in evaluation:
                    print("Missing " + field + " from custom evaluation.")
                    missing_fields = True

            if not missing_fields:
                latest_evaluations.append(evaluation)
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    else:
        missing_fields = False
        for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
            if field not in compliance_result:
                print("Missing " + field + " from custom evaluation.")
                missing_fields = True
        if not missing_fields:
            evaluations.append(compliance_result)

    # Put together the request that reports the evaluation status
    resultToken = event['resultToken']
    testMode = False
    if resultToken == 'TESTMODE':
        # Used solely for RDK test to skip actual put_evaluation API call
        testMode = True
    # Invoke the Config API to report the result of the evaluation
    evaluation_copy = []
    evaluation_copy = evaluations[:]
    while(evaluation_copy):
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluation_copy[:100], ResultToken=resultToken, TestMode=testMode)
        del evaluation_copy[:100]
    # Used solely for RDK test to be able to test Lambda function
    # print("overall finding: ")
    print(evaluations)
    for account in non_c_account:
        print(account)
    
    return evaluations, non_c_account

def is_internal_error(exception):
    return ((not isinstance(exception, botocore.exceptions.ClientError)) or exception.response['Error']['Code'].startswith('5')
            or 'InternalError' in exception.response['Error']['Code'] or 'ServiceError' in exception.response['Error']['Code'])

def build_internal_error_response(internalErrorMessage, internalErrorDetails=None):
    return build_error_response(internalErrorMessage, internalErrorDetails, 'InternalError', 'InternalError')

def build_error_response(internalErrorMessage, internalErrorDetails=None, customerErrorCode=None, customerErrorMessage=None):
    error_response = {
        'internalErrorMessage': internalErrorMessage,
        'internalErrorDetails': internalErrorDetails,
        'customerErrorMessage': customerErrorMessage,
        'customerErrorCode': customerErrorCode
    }
    print(error_response)
    return error_response