#!/usr/bin/env python3
"""
IAM Risk Assessment Tool

This script is a data gathering and risk assessment tool.
It uses boto3 to gather IAM data from AWS accounts and immediately performs
comprehensive risk assessment analysis.
"""

import boto3
import csv
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iam_risk_assessment.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AccessKeyInfo:
    """Data class to store access key information and risk factors"""
    account_id: str
    username: str
    user_id: str
    arn: str
    key_id: str
    status: str
    last_used: Optional[str]
    created: Optional[str]
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    has_console_access: bool = False
    has_mfa: bool = False
    managed_policies: List[str] = field(default_factory=list)
    inline_policies: List[str] = field(default_factory=list)
    group_policies: Dict[str, Dict] = field(default_factory=dict)

class IAMCompleteAssessment:
    """Complete IAM assessment tool - data gathering + risk analysis"""
    
    def __init__(self, profile_name: Optional[str] = None, shared_timestamp: Optional[str] = None, report_only: bool = False, skip_file_writing: bool = False):
        self.timestamp = shared_timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = Path(f"gathered_data_{self.timestamp}")
        self.output_dir.mkdir(exist_ok=True)
        self.assessment_dir = Path(f"assessment_output_{self.timestamp}")
        self.assessment_dir.mkdir(exist_ok=True)
        
        if not report_only:
            # Initialize boto3 session
            if profile_name:
                self.session = boto3.Session(profile_name=profile_name)
            else:
                self.session = boto3.Session()
            
            # Set default region if not specified
            if not self.session.region_name:
                self.session = boto3.Session(profile_name=profile_name, region_name='us-east-1') if profile_name else boto3.Session(region_name='us-east-1')
            
            self.iam_client = self.session.client('iam')
            self.sts_client = self.session.client('sts')
            self.cloudtrail_client = self.session.client('cloudtrail')
            
            # Get current account info
            try:
                self.current_account = self.sts_client.get_caller_identity()
                logger.info(f"Connected to AWS Account: {self.current_account['Account']}")
            except NoCredentialsError:
                logger.error("No AWS credentials found. Please configure your credentials.")
                raise
        else:
            # Report-only mode - no AWS clients needed
            self.session = None
            self.iam_client = None
            self.sts_client = None
            self.cloudtrail_client = None
            self.current_account = {'Account': 'consolidated'}
        
        # Risk assessment data
        self.access_keys: List[AccessKeyInfo] = []
        self.accounts: Dict[str, str] = {}
        self.is_management_account = False
        self.cloudtrail_events: List[Dict] = []
        self.admin_policies = {
            'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess',
            'AWSCloudTrailFullAccess', 'AmazonEC2FullAccess'
        }
        self.iam_key_policies = {
            'IAMFullAccess', 'IAMUserChangePassword', 'IAMReadOnlyAccess'
        }
        
        # Store gathered data for analysis
        self.gathered_data = {}
        self.skip_file_writing = skip_file_writing

    def write_csv(self, filename: str, data: List[Dict], fieldnames: List[str]):
        """Write data to CSV file with timestamp and account ID"""
        if self.skip_file_writing:
            logger.info(f"Skipping file write for {filename} (multi-profile mode)")
            return data
            
        account_id = self.current_account['Account']
        base_name = filename.split('.')[0]
        timestamped_filename = f"{base_name}_{account_id}_{self.timestamp}.csv"
        filepath = self.output_dir / timestamped_filename
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            
            logger.info(f"Written {len(data)} records to {filepath}")
            return data
        except Exception as e:
            logger.error(f"Error writing {filepath}: {e}")
            raise

    def gather_account_info(self) -> List[Dict]:
        """Gather AWS account information"""
        logger.info("Gathering account information...")
        
        account_id = self.current_account['Account']
        
        # Try to get account name using account API
        try:
            account_client = self.session.client('account')
            account_info = account_client.get_account_information()
            account_name = account_info.get('AccountName', f"Account-{account_id}")
        except ClientError as e:
            logger.warning(f"Unable to get account name: {e}")
            account_name = f"Account-{account_id}"
        except Exception as e:
            logger.warning(f"Error accessing account service: {e}")
            account_name = f"Account-{account_id}"
        
        # Check if this is the management account
        try:
            orgs_client = self.session.client('organizations')
            org_info = orgs_client.describe_organization()
            management_account_id = org_info['Organization']['MasterAccountId']
            self.is_management_account = (account_id == management_account_id)
            logger.info(f"Management account check: {self.is_management_account}")
        except ClientError as e:
            logger.warning(f"Unable to check organization info: {e}")
            self.is_management_account = False
        except Exception as e:
            logger.warning(f"Error accessing organizations service: {e}")
            self.is_management_account = False
        
        accounts = [{
            'AccountID': f"ID,{account_id}",
            'AccountName': account_name
        }]
        
        logger.info(f"Using current account: {account_id} ({account_name})")
        return self.write_csv('AWS-Accounts.csv', accounts, ['AccountID', 'AccountName'])

    def gather_iam_users(self) -> List[Dict]:
        """Gather all IAM users"""
        logger.info("Gathering IAM users...")
        
        users = []
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            users.extend(page['Users'])
        
        logger.info(f"Found {len(users)} IAM users")
        return users

    def gather_access_keys(self) -> List[Dict]:
        """Gather IAM user access keys"""
        logger.info("Gathering access keys...")
        
        account_id = self.current_account['Account']
        access_keys_data = []
        users = self.gather_iam_users()
        
        for user in users:
            username = user['UserName']
            user_id = user['UserId']
            arn = user['Arn']
            
            try:
                keys_response = self.iam_client.list_access_keys(UserName=username)
                
                if not keys_response['AccessKeyMetadata']:
                    access_keys_data.append({
                        'AccountID': f"ID,{account_id}",
                        'UserName': username,
                        'UserId': user_id,
                        'Arn': arn,
                        'KeyId': 'NO Access Key Found',
                        'KeyStatus': '',
                        'LastTimeUsed': '',
                        'CreationTime': ''
                    })
                else:
                    for key_metadata in keys_response['AccessKeyMetadata']:
                        key_id = key_metadata['AccessKeyId']
                        status = key_metadata['Status']
                        created = key_metadata['CreateDate'].strftime('%Y-%m-%d %H:%M:%S')
                        
                        last_used = ''
                        try:
                            last_used_response = self.iam_client.get_access_key_last_used(AccessKeyId=key_id)
                            if 'LastUsedDate' in last_used_response['AccessKeyLastUsed']:
                                last_used = last_used_response['AccessKeyLastUsed']['LastUsedDate'].strftime('%Y-%m-%d %H:%M:%S')
                        except ClientError as e:
                            logger.warning(f"Unable to get last used date for key {key_id}: {e}")
                        
                        access_keys_data.append({
                            'AccountID': f"ID,{account_id}",
                            'UserName': username,
                            'UserId': user_id,
                            'Arn': arn,
                            'KeyId': key_id,
                            'KeyStatus': status,
                            'LastTimeUsed': last_used,
                            'CreationTime': created
                        })
            
            except ClientError as e:
                logger.error(f"Error getting access keys for user {username}: {e}")
        
        logger.info(f"Gathered {len(access_keys_data)} access key records")
        return self.write_csv('IAMUser-AccessKey.csv', access_keys_data, 
                             ['AccountID', 'UserName', 'UserId', 'Arn', 'KeyId', 'KeyStatus', 'LastTimeUsed', 'CreationTime'])

    def gather_console_login_profiles(self) -> List[Dict]:
        """Gather console login profile information"""
        logger.info("Gathering console login profiles...")
        
        account_id = self.current_account['Account']
        console_data = []
        users = self.gather_iam_users()
        
        for user in users:
            username = user['UserName']
            user_id = user['UserId']
            arn = user['Arn']
            
            password_last_used = ''
            
            try:
                self.iam_client.get_login_profile(UserName=username)
                if 'PasswordLastUsed' in user:
                    password_last_used = user['PasswordLastUsed'].strftime('%Y-%m-%d %H:%M:%S')
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.warning(f"Error checking login profile for {username}: {e}")
            
            console_data.append({
                'AccountID': f"ID,{account_id}",
                'UserName': username,
                'UserId': user_id,
                'Arn': arn,
                'LastPasswordUsed': password_last_used if password_last_used else 'none'
            })
        
        logger.info(f"Gathered {len(console_data)} console login records")
        return self.write_csv('IAMUser-ConsoleLogin.csv', console_data,
                             ['AccountID', 'UserName', 'UserId', 'Arn', 'LastPasswordUsed'])

    def gather_mfa_devices(self) -> List[Dict]:
        """Gather MFA device information"""
        logger.info("Gathering MFA devices...")
        
        account_id = self.current_account['Account']
        mfa_data = []
        users = self.gather_iam_users()
        
        for user in users:
            username = user['UserName']
            user_id = user['UserId']
            arn = user['Arn']
            
            try:
                mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                
                if not mfa_devices['MFADevices']:
                    mfa_data.append({
                        'AccountID': f"ID,{account_id}",
                        'UserName': username,
                        'UserId': user_id,
                        'Arn': arn,
                        'MFAserialNumber': 'false'
                    })
                else:
                    for device in mfa_devices['MFADevices']:
                        mfa_data.append({
                            'AccountID': f"ID,{account_id}",
                            'UserName': username,
                            'UserId': user_id,
                            'Arn': arn,
                            'MFAserialNumber': device['SerialNumber']
                        })
            
            except ClientError as e:
                logger.error(f"Error getting MFA devices for user {username}: {e}")
        
        logger.info(f"Gathered {len(mfa_data)} MFA records")
        return self.write_csv('IAMUser-MFA.csv', mfa_data,
                             ['AccountID', 'UserName', 'UserId', 'Arn', 'MFAserialNumber'])

    def gather_user_policies(self) -> List[Dict]:
        """Gather user attached policies and group memberships"""
        logger.info("Gathering user policies...")
        
        account_id = self.current_account['Account']
        policies_data = []
        users = self.gather_iam_users()
        
        for user in users:
            username = user['UserName']
            user_id = user['UserId']
            arn = user['Arn']
            
            try:
                attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
                aws_managed = []
                customer_managed = []
                
                for policy in attached_policies['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    policy_name = policy['PolicyName']
                    
                    if ':aws:policy/' in policy_arn:
                        aws_managed.append(policy_name)
                    else:
                        customer_managed.append(policy_name)
                
                inline_policies = self.iam_client.list_user_policies(UserName=username)
                inline_policy_names = inline_policies['PolicyNames']
                
                groups = self.iam_client.list_groups_for_user(UserName=username)
                group_names = [g['GroupName'] for g in groups['Groups']]
                
                policies_data.append({
                    'AccountID': f"ID,{account_id}",
                    'UserName': username,
                    'UserId': user_id,
                    'Arn': arn,
                    'InlinePolicy': str(inline_policy_names) if inline_policy_names else '',
                    'AWSManagedPolicy': str(aws_managed) if aws_managed else '',
                    'CustomerManagedPolicy': str(customer_managed) if customer_managed else '',
                    'Groups': str(group_names) if group_names else '',
                    'PermissionsBoundary': '',
                    'TotalManagedPoliciesAttached': len(aws_managed) + len(customer_managed)
                })
            
            except ClientError as e:
                logger.error(f"Error getting policies for user {username}: {e}")
        
        logger.info(f"Gathered {len(policies_data)} user policy records")
        return self.write_csv('IAMUser-PoliciesSummary.csv', policies_data,
                             ['AccountID', 'UserName', 'UserId', 'Arn', 'InlinePolicy', 'AWSManagedPolicy',
                              'CustomerManagedPolicy', 'Groups', 'PermissionsBoundary', 'TotalManagedPoliciesAttached'])

    def gather_user_inline_policies(self) -> List[Dict]:
        """Gather detailed inline policy documents"""
        logger.info("Gathering user inline policy documents...")
        
        account_id = self.current_account['Account']
        inline_data = []
        users = self.gather_iam_users()
        
        for user in users:
            username = user['UserName']
            user_id = user['UserId']
            arn = user['Arn']
            
            try:
                inline_policies = self.iam_client.list_user_policies(UserName=username)
                
                for policy_name in inline_policies['PolicyNames']:
                    policy_doc = self.iam_client.get_user_policy(
                        UserName=username,
                        PolicyName=policy_name
                    )
                    
                    inline_data.append({
                        'AccountID': f"ID,{account_id}",
                        'UserName': username,
                        'UserId': user_id,
                        'Arn': arn,
                        'PolicyName': policy_name,
                        'DocumentPolicy': str(policy_doc['PolicyDocument'])
                    })
            
            except ClientError as e:
                logger.error(f"Error getting inline policies for user {username}: {e}")
        
        logger.info(f"Gathered {len(inline_data)} inline policy records")
        return self.write_csv('IAMUser-InlinePoliciesChecks.csv', inline_data,
                             ['AccountID', 'UserName', 'UserId', 'Arn', 'PolicyName', 'DocumentPolicy'])

    def gather_group_policies(self) -> List[Dict]:
        """Gather group attached policies"""
        logger.info("Gathering group policies...")
        
        account_id = self.current_account['Account']
        group_policies_data = []
        
        try:
            paginator = self.iam_client.get_paginator('list_groups')
            
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_name = group['GroupName']
                    group_id = group['GroupId']
                    group_arn = group['Arn']
                    
                    try:
                        attached_policies = self.iam_client.list_attached_group_policies(GroupName=group_name)
                        aws_managed = []
                        customer_managed = []
                        
                        for policy in attached_policies['AttachedPolicies']:
                            policy_arn = policy['PolicyArn']
                            policy_name = policy['PolicyName']
                            
                            if ':aws:policy/' in policy_arn:
                                aws_managed.append(policy_name)
                            else:
                                customer_managed.append(policy_name)
                        
                        inline_policies = self.iam_client.list_group_policies(GroupName=group_name)
                        inline_policy_names = inline_policies['PolicyNames']
                        
                        group_policies_data.append({
                            'AccountID': f"ID,{account_id}",
                            'GroupName': group_name,
                            'GroupId': group_id,
                            'Arn': group_arn,
                            'InlinePolicy': str(inline_policy_names) if inline_policy_names else '',
                            'AWSManagedPolicy': str(aws_managed) if aws_managed else '',
                            'CustomerManagedPolicy': str(customer_managed) if customer_managed else ''
                        })
                    
                    except ClientError as e:
                        logger.error(f"Error getting policies for group {group_name}: {e}")
        
        except ClientError as e:
            logger.error(f"Error listing groups: {e}")
        
        logger.info(f"Gathered {len(group_policies_data)} group policy records")
        return self.write_csv('IAMGroup-PoliciesSummary.csv', group_policies_data,
                             ['AccountID', 'GroupName', 'GroupId', 'Arn', 'InlinePolicy', 'AWSManagedPolicy', 'CustomerManagedPolicy'])

    def gather_group_inline_policies(self) -> List[Dict]:
        """Gather detailed group inline policy documents"""
        logger.info("Gathering group inline policy documents...")
        
        account_id = self.current_account['Account']
        inline_data = []
        
        try:
            paginator = self.iam_client.get_paginator('list_groups')
            
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_name = group['GroupName']
                    group_id = group['GroupId']
                    group_arn = group['Arn']
                    
                    try:
                        inline_policies = self.iam_client.list_group_policies(GroupName=group_name)
                        
                        for policy_name in inline_policies['PolicyNames']:
                            policy_doc = self.iam_client.get_group_policy(
                                GroupName=group_name,
                                PolicyName=policy_name
                            )
                            
                            inline_data.append({
                                'AccountID': f"ID,{account_id}",
                                'GroupName': group_name,
                                'GroupId': group_id,
                                'Arn': group_arn,
                                'PolicyName': policy_name,
                                'DocumentPolicy': str(policy_doc['PolicyDocument'])
                            })
                    
                    except ClientError as e:
                        logger.error(f"Error getting inline policies for group {group_name}: {e}")
        
        except ClientError as e:
            logger.error(f"Error listing groups: {e}")
        
        logger.info(f"Gathered {len(inline_data)} group inline policy records")
        return self.write_csv('IAMGroup-InlinePoliciesChecks.csv', inline_data,
                             ['AccountID', 'GroupName', 'GroupId', 'Arn', 'PolicyName', 'DocumentPolicy'])

    def gather_all_data(self):
        """Gather all IAM data and store for analysis"""
        logger.info("Starting IAM data gathering process...")
        
        try:
            self.gathered_data['accounts'] = self.gather_account_info()
            self.gathered_data['access_keys'] = self.gather_access_keys()
            self.gathered_data['console_login'] = self.gather_console_login_profiles()
            self.gathered_data['mfa'] = self.gather_mfa_devices()
            self.gathered_data['user_policies'] = self.gather_user_policies()
            self.gathered_data['user_inline'] = self.gather_user_inline_policies()
            self.gathered_data['group_policies'] = self.gather_group_policies()
            self.gathered_data['group_inline'] = self.gather_group_inline_policies()
            
            logger.info("=== IAM data gathering completed ===")
            
        except Exception as e:
            logger.error(f"Error during data gathering: {e}")
            raise

    # Risk Assessment Methods
    def parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime object"""
        if not date_str or date_str.lower() in ['none', 'null', '']:
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                return datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                logger.warning(f"Unable to parse date: {date_str}")
                return None

    def extract_policies_from_string(self, policy_str: str) -> List[str]:
        """Extract policy names from string representation"""
        if not policy_str or policy_str.lower() in ['none', 'null', '']:
            return []
        
        if policy_str.startswith('[') and policy_str.endswith(']'):
            try:
                policies = policy_str[1:-1].replace("'", "").replace('"', '').split(',')
                return [p.strip() for p in policies if p.strip()]
            except:
                return []
        return [policy_str.strip()]

    def has_admin_privileges(self, key_info: AccessKeyInfo) -> bool:
        """Check if access key has admin privileges"""
        for policy in key_info.managed_policies:
            if (any(admin_policy in policy for admin_policy in self.admin_policies) or 
                'FullAccess' in policy):
                return True
        
        for group_data in key_info.group_policies.values():
            managed_policies = group_data.get('ManagedPolicy', {})
            if isinstance(managed_policies, dict):
                for policy_name in managed_policies.keys():
                    if (any(admin_policy in policy_name for admin_policy in self.admin_policies) or 
                        'FullAccess' in policy_name):
                        return True
        
        group_policies = getattr(key_info, 'group_managed_policies', [])
        group_inline_policies = getattr(key_info, 'group_inline_policies', [])
        
        for policy in group_policies + group_inline_policies:
            if (any(admin_policy in policy for admin_policy in self.admin_policies) or 
                'FullAccess' in policy):
                return True
        
        return False

    def has_risky_inline_policies(self, key_info: AccessKeyInfo) -> bool:
        """Check if inline policies contain risky permissions"""
        risky_patterns = [
            '*', 'admin', 'full', 'all', 'root', 'super',
            'iam:', 'sts:', 'organizations:', 'account:',
            'createaccesskey', 'deleteaccesskey', 'updateaccesskey',
            'createrole', 'deleterole', 'attachrolepolicy',
            'createuser', 'deleteuser', 'attachuserpolicy'
        ]
        
        user_inline_docs = {}
        for row in self.gathered_data['user_inline']:
            username = row.get('UserName', '')
            policy_doc = row.get('DocumentPolicy', '')
            if username == key_info.username and policy_doc:
                user_inline_docs[username] = policy_doc
        
        if key_info.username in user_inline_docs:
            policy_content = user_inline_docs[key_info.username].lower()
            if any(pattern in policy_content for pattern in risky_patterns):
                return True
        
        return False

    def has_iam_key_permissions(self, key_info: AccessKeyInfo) -> bool:
        """Check if access key can create/activate IAM keys"""
        for policy in key_info.managed_policies:
            if any(iam_policy in policy for iam_policy in self.iam_key_policies):
                return True
        
        for policy in key_info.inline_policies:
            if 'iam:' in policy.lower() or 'createaccesskey' in policy.lower():
                return True
        
        group_policies = getattr(key_info, 'group_managed_policies', [])
        group_inline_policies = getattr(key_info, 'group_inline_policies', [])
        
        for policy in group_policies:
            if any(iam_policy in policy for iam_policy in self.iam_key_policies):
                return True
        
        for policy in group_inline_policies:
            if 'iam:' in policy.lower() or 'createaccesskey' in policy.lower():
                return True
        
        return False
    
    def get_active_regions(self) -> List[str]:
        """Get list of active AWS regions"""
        try:
            ec2_client = self.session.client('ec2')
            response = ec2_client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            logger.warning(f"Unable to get regions, using default: {e}")
            return ['us-east-1']
    
    def check_cloudtrail_activity(self, access_key_id: str) -> Dict[str, bool]:
        """Check CloudTrail activity for access key in last 90 days across all regions"""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=90)
        
        all_events = []
        regions = self.get_active_regions()
        
        for region in regions:
            try:
                cloudtrail_client = self.session.client('cloudtrail', region_name=region)
                response = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'AccessKeyId',
                            'AttributeValue': access_key_id
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=50
                )
                
                events = response.get('Events', [])
                for event in events:
                    event['Region'] = region
                all_events.extend(events)
                
            except ClientError as e:
                logger.warning(f"Unable to check CloudTrail in region {region} for key {access_key_id}: {e}")
                continue
            except Exception as e:
                logger.warning(f"Error checking CloudTrail in region {region} for key {access_key_id}: {e}")
                continue
        
        # Add events to global collection
        for event in all_events:
            event['AccessKeyId'] = access_key_id
            event['AccountId'] = self.current_account['Account']
        self.cloudtrail_events.extend(all_events)
        
        if all_events:
            logger.info(f"Found {len(all_events)} CloudTrail events for key {access_key_id}")
        else:
            logger.info(f"No CloudTrail events found for key {access_key_id} across {len(regions)} regions")
        
        has_activity = len(all_events) > 0
        has_write_operations = any(not event.get('ReadOnly', True) for event in all_events)
        
        return {
            'has_activity': has_activity,
            'has_write_operations': has_write_operations
        }
    
    def write_consolidated_csv(self, filename: str, data: List[Dict], fieldnames: List[str]):
        """Write consolidated data to CSV file with timestamp only"""
        timestamped_filename = f"{filename.split('.')[0]}_{self.timestamp}.csv"
        filepath = self.output_dir / timestamped_filename
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            
            logger.info(f"Written {len(data)} consolidated records to {filepath}")
            return data
        except Exception as e:
            logger.error(f"Error writing {filepath}: {e}")
            raise
    
    def save_all_cloudtrail_events(self):
        """Save all CloudTrail events to single CSV file"""
        try:
            account_id = self.current_account['Account']
            filename = f"CloudTrail-Events_{account_id}_{self.timestamp}.csv"
            filepath = self.output_dir / filename
            
            fieldnames = ['AccountId', 'AccessKeyId', 'EventTime', 'EventName', 'EventSource', 'Region', 'ReadOnly', 'UserName', 'SourceIPAddress', 'UserAgent']
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for event in self.cloudtrail_events:
                    # Extract CloudTrailEvent details if available
                    cloudtrail_event = event.get('CloudTrailEvent')
                    source_ip = ''
                    user_agent = ''
                    
                    if cloudtrail_event:
                        try:
                            ct_data = json.loads(cloudtrail_event) if isinstance(cloudtrail_event, str) else cloudtrail_event
                            source_ip = ct_data.get('sourceIPAddress', '')
                            user_agent = ct_data.get('userAgent', '')
                        except:
                            pass
                    
                    writer.writerow({
                        'AccountId': event.get('AccountId', ''),
                        'AccessKeyId': event.get('AccessKeyId', ''),
                        'EventTime': event.get('EventTime', '').strftime('%Y-%m-%d %H:%M:%S') if event.get('EventTime') else '',
                        'EventName': event.get('EventName', ''),
                        'EventSource': event.get('EventSource', ''),
                        'Region': event.get('Region', ''),
                        'ReadOnly': event.get('ReadOnly', ''),
                        'UserName': event.get('Username', ''),
                        'SourceIPAddress': source_ip,
                        'UserAgent': user_agent
                    })
            
            logger.info(f"Saved {len(self.cloudtrail_events)} CloudTrail events to {filepath}")
        
        except Exception as e:
            logger.error(f"Error saving CloudTrail events: {e}")
    
    def save_consolidated_cloudtrail_events(self):
        """Save consolidated CloudTrail events to single CSV file"""
        try:
            filename = f"CloudTrail-Events_{self.timestamp}.csv"
            filepath = self.output_dir / filename
            
            fieldnames = ['AccountId', 'AccessKeyId', 'EventTime', 'EventName', 'EventSource', 'Region', 'ReadOnly', 'UserName', 'SourceIPAddress', 'UserAgent']
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for event in self.cloudtrail_events:
                    # Extract CloudTrailEvent details if available
                    cloudtrail_event = event.get('CloudTrailEvent')
                    source_ip = ''
                    user_agent = ''
                    
                    if cloudtrail_event:
                        try:
                            ct_data = json.loads(cloudtrail_event) if isinstance(cloudtrail_event, str) else cloudtrail_event
                            source_ip = ct_data.get('sourceIPAddress', '')
                            user_agent = ct_data.get('userAgent', '')
                        except:
                            pass
                    
                    writer.writerow({
                        'AccountId': event.get('AccountId', ''),
                        'AccessKeyId': event.get('AccessKeyId', ''),
                        'EventTime': event.get('EventTime', '').strftime('%Y-%m-%d %H:%M:%S') if event.get('EventTime') else '',
                        'EventName': event.get('EventName', ''),
                        'EventSource': event.get('EventSource', ''),
                        'Region': event.get('Region', ''),
                        'ReadOnly': event.get('ReadOnly', ''),
                        'UserName': event.get('Username', ''),
                        'SourceIPAddress': source_ip,
                        'UserAgent': user_agent
                    })
            
            logger.info(f"Saved {len(self.cloudtrail_events)} consolidated CloudTrail events to {filepath}")
        
        except Exception as e:
            logger.error(f"Error saving consolidated CloudTrail events: {e}")

    def load_accounts_from_data(self):
        """Load AWS account data from gathered data"""
        logger.info("Loading AWS account data...")
        
        for row in self.gathered_data['accounts']:
            account_id = row.get('AccountID', '').strip()
            account_name = row.get('AccountName', '').strip()
            if account_id and account_name:
                self.accounts[account_id] = account_name
        
        logger.info(f"Loaded {len(self.accounts)} AWS accounts")

    def load_access_keys_from_data(self):
        """Load access key data from gathered data"""
        logger.info("Loading access key data...")
        
        for row in self.gathered_data['access_keys']:
            if row.get('KeyId') == 'NO Access Key Found' or not row.get('KeyId'):
                continue
            
            key_info = AccessKeyInfo(
                account_id=row.get('AccountID', '').replace('ID,', '').replace('"', ''),
                username=row.get('UserName', ''),
                user_id=row.get('UserId', ''),
                arn=row.get('Arn', ''),
                key_id=row.get('KeyId', ''),
                status=row.get('KeyStatus', ''),
                last_used=row.get('LastTimeUsed'),
                created=row.get('CreationTime')
            )
            self.access_keys.append(key_info)
        
        logger.info(f"Loaded {len(self.access_keys)} access keys")

    def enrich_with_console_access_from_data(self):
        """Add console access information from gathered data"""
        logger.info("Enriching with console access data...")
        
        console_users = {}
        for row in self.gathered_data['console_login']:
            username = row.get('UserName', '')
            last_password_used = row.get('LastPasswordUsed')
            has_console = last_password_used and last_password_used.lower() != 'none'
            console_users[username] = has_console
        
        for key_info in self.access_keys:
            key_info.has_console_access = console_users.get(key_info.username, False)

    def enrich_with_mfa_status_from_data(self):
        """Add MFA status information from gathered data"""
        logger.info("Enriching with MFA data...")
        
        mfa_users = defaultdict(bool)
        for row in self.gathered_data['mfa']:
            username = row.get('UserName', '')
            mfa_serial = row.get('MFAserialNumber', '')
            if mfa_serial and mfa_serial.lower() != 'false':
                mfa_users[username] = True
        
        for key_info in self.access_keys:
            key_info.has_mfa = mfa_users.get(key_info.username, False)

    def enrich_with_policies_from_data(self):
        """Add policy information from gathered data"""
        logger.info("Enriching with policy data...")
        
        user_policy_map = {}
        user_inline_map = defaultdict(list)
        group_managed_map = defaultdict(list)
        group_inline_map = defaultdict(list)
        
        # Process user policies
        for row in self.gathered_data['user_policies']:
            username = row.get('UserName', '')
            aws_managed = self.extract_policies_from_string(row.get('AWSManagedPolicy', ''))
            customer_managed = self.extract_policies_from_string(row.get('CustomerManagedPolicy', ''))
            groups_str = row.get('Groups', '')
            
            groups_data = {}
            if groups_str and groups_str != '':
                try:
                    groups_data = eval(groups_str) if groups_str.startswith('{') else {}
                except:
                    pass
            
            user_policy_map[username] = {
                'managed': aws_managed + customer_managed,
                'groups': groups_data
            }
        
        # Process user inline policies
        for row in self.gathered_data['user_inline']:
            username = row.get('UserName', '')
            policy_name = row.get('PolicyName', '')
            if policy_name:
                user_inline_map[username].append(policy_name)
        
        # Process group managed policies
        for row in self.gathered_data['group_policies']:
            group_name = row.get('GroupName', '')
            aws_managed = self.extract_policies_from_string(row.get('AWSManagedPolicy', ''))
            customer_managed = self.extract_policies_from_string(row.get('CustomerManagedPolicy', ''))
            group_managed_map[group_name].extend(aws_managed + customer_managed)
        
        # Process group inline policies
        for row in self.gathered_data['group_inline']:
            group_name = row.get('GroupName', '')
            policy_name = row.get('PolicyName', '')
            if policy_name:
                group_inline_map[group_name].append(policy_name)
        
        # Apply to access keys
        for key_info in self.access_keys:
            if key_info.username in user_policy_map:
                policy_data = user_policy_map[key_info.username]
                key_info.managed_policies = policy_data['managed']
                key_info.group_policies = policy_data['groups']
            
            key_info.inline_policies = user_inline_map.get(key_info.username, [])
            
            user_group_managed = []
            user_group_inline = []
            
            for group_name in key_info.group_policies.keys():
                user_group_managed.extend(group_managed_map.get(group_name, []))
                user_group_inline.extend(group_inline_map.get(group_name, []))
            
            key_info.group_managed_policies = user_group_managed
            key_info.group_inline_policies = user_group_inline

    def calculate_risk_scores(self):
        """Calculate risk scores for each access key"""
        logger.info("Calculating risk scores...")
        current_time = datetime.now()
        ninety_days_ago = current_time - timedelta(days=90)
        one_year_ago = current_time - timedelta(days=360)
        
        for key_info in self.access_keys:
            risk_score = 0
            risk_factors = []
            
            if key_info.status.upper() == 'INACTIVE':
                key_info.risk_score = 0
                key_info.risk_factors = []
                continue
            
            if key_info.status.upper() == 'ACTIVE':
                last_used_date = self.parse_date(key_info.last_used)
                if last_used_date and last_used_date >= ninety_days_ago:
                    risk_score += 1
                    risk_factors.append("Active key used in last 90 days")
                
                created_date = self.parse_date(key_info.created)
                if created_date and created_date <= ninety_days_ago:
                    risk_score += 1
                    risk_factors.append("Active key created 90+ days ago")
                
                if created_date and created_date <= one_year_ago:
                    risk_score += 1
                    risk_factors.append("Active key created 360+ days ago")
                
                if self.has_admin_privileges(key_info):
                    risk_score += 1
                    risk_factors.append("Active key has admin/power user privileges")
                
                if self.has_risky_inline_policies(key_info):
                    risk_score += 1
                    risk_factors.append("Active key has risky inline policies")
                
                if (self.has_admin_privileges(key_info) and 
                    last_used_date and last_used_date >= ninety_days_ago):
                    risk_score += 1
                    risk_factors.append("Active key with admin access used in last 90 days")
                
                if self.has_iam_key_permissions(key_info):
                    risk_score += 1
                    risk_factors.append("Active key can create/manage IAM access keys")
                
                if key_info.inline_policies and not self.has_risky_inline_policies(key_info):
                    risk_score += 0.5
                    risk_factors.append("Active key has custom inline policies")
            
            # CloudTrail activity check (only for keys used in last 90 days)
            if key_info.status.upper() == 'ACTIVE':
                last_used_date = self.parse_date(key_info.last_used)
                if last_used_date and last_used_date >= ninety_days_ago:
                    logger.info(f"Checking CloudTrail activity for key {key_info.key_id}")
                    cloudtrail_activity = self.check_cloudtrail_activity(key_info.key_id)
                    if cloudtrail_activity['has_activity']:
                        if cloudtrail_activity['has_write_operations']:
                            risk_score += 2
                            risk_factors.append("Active key has write operations in CloudTrail (last 90 days)")
                            logger.info(f"Key {key_info.key_id} has write operations in CloudTrail")
                        else:
                            risk_score += 1
                            risk_factors.append("Active key has CloudTrail activity in last 90 days")
                            logger.info(f"Key {key_info.key_id} has read-only CloudTrail activity")
                    else:
                        logger.info(f"No CloudTrail events found for key {key_info.key_id}")
            
            if key_info.has_console_access:
                risk_score += 1
                risk_factors.append("Associated user has console access")
            
            if key_info.has_console_access and not key_info.has_mfa:
                risk_score += 1
                risk_factors.append("Associated user doesn't have MFA enabled")
            
            # Check account environment risk
            if self.is_management_account:
                risk_score += 2
                risk_factors.append("Access key in management account")
            
            account_name = self.accounts.get(key_info.account_id, '').lower()
            if 'production' in account_name or 'prod' in account_name:
                risk_score += 2
                risk_factors.append("Access key in production account")
            elif 'staging' in account_name:
                risk_score += 1
                risk_factors.append("Access key in staging account")
            
            key_info.risk_score = int(risk_score)
            key_info.risk_factors = risk_factors

    def generate_csv_reports(self):
        """Generate CSV reports for structured data analysis"""
        logger.info("Generating CSV reports...")
        
        sorted_keys = sorted(self.access_keys, key=lambda x: x.risk_score, reverse=True)
        
        detailed_csv = self.assessment_dir / f"iam_risk_assessment_detailed_{self.timestamp}.csv"
        
        with open(detailed_csv, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Username', 'Account_ID', 'Account_Name', 'Key_ID', 'Status', 'Created', 'Last_Used',
                'Risk_Score', 'Risk_Factors', 'Managed_Policies', 'Inline_Policies',
                'Group_Managed_Policies', 'Group_Inline_Policies', 'Console_Access', 'MFA_Enabled'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for key in sorted_keys:
                account_name = self.accounts.get(key.account_id, 'Unknown')
                writer.writerow({
                    'Username': key.username,
                    'Account_ID': key.account_id,
                    'Account_Name': account_name,
                    'Key_ID': key.key_id,
                    'Status': key.status,
                    'Created': key.created or 'Unknown',
                    'Last_Used': key.last_used or 'Never',
                    'Risk_Score': key.risk_score,
                    'Risk_Factors': '; '.join(key.risk_factors),
                    'Managed_Policies': '; '.join(key.managed_policies),
                    'Inline_Policies': '; '.join(key.inline_policies),
                    'Group_Managed_Policies': '; '.join(getattr(key, 'group_managed_policies', [])),
                    'Group_Inline_Policies': '; '.join(getattr(key, 'group_inline_policies', [])),
                    'Console_Access': 'Yes' if key.has_console_access else 'No',
                    'MFA_Enabled': 'Yes' if key.has_mfa else 'No'
                })
        
        summary_csv = self.assessment_dir / f"iam_risk_assessment_summary_{self.timestamp}.csv"
        high_risk_keys = [key for key in sorted_keys if key.risk_score >= 5]
        
        with open(summary_csv, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Username', 'Account_ID', 'Account_Name', 'Key_ID', 'Risk_Score', 'Status', 'Top_Risk_Factors']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for key in high_risk_keys:
                account_name = self.accounts.get(key.account_id, 'Unknown')
                writer.writerow({
                    'Username': key.username,
                    'Account_ID': key.account_id,
                    'Account_Name': account_name,
                    'Key_ID': key.key_id,
                    'Risk_Score': key.risk_score,
                    'Status': key.status,
                    'Top_Risk_Factors': '; '.join(key.risk_factors[:3])
                })
        
        logger.info(f"CSV reports generated: {detailed_csv}, {summary_csv}")
        return detailed_csv, summary_csv

    def generate_report(self) -> str:
        """Generate comprehensive risk assessment report"""
        logger.info("Generating risk assessment report...")
        
        total_keys = len(self.access_keys)
        active_keys = sum(1 for key in self.access_keys if key.status.upper() == 'ACTIVE')
        inactive_keys = total_keys - active_keys
        
        sorted_keys = sorted(self.access_keys, key=lambda x: x.risk_score, reverse=True)
        high_risk_keys = [key for key in sorted_keys if key.risk_score >= 5]
        
        report = []
        report.append("=" * 80)
        report.append("IAM ACCESS KEY RISK ASSESSMENT REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        account_stats = defaultdict(int)
        for key in self.access_keys:
            account_stats[key.account_id] += 1
        
        # Normalize account IDs and merge duplicates
        normalized_stats = defaultdict(int)
        normalized_accounts = {}
        
        for account_id, account_name in self.accounts.items():
            normalized_id = account_id.replace('ID,', '').replace('"', '')
            normalized_accounts[normalized_id] = account_name
            if normalized_id in account_stats:
                normalized_stats[normalized_id] += account_stats[normalized_id]
        
        # Add any remaining stats that weren't in accounts dict
        for account_id, count in account_stats.items():
            normalized_id = account_id.replace('ID,', '').replace('"', '')
            if normalized_id not in normalized_stats:
                normalized_stats[normalized_id] = count
                if normalized_id not in normalized_accounts:
                    normalized_accounts[normalized_id] = 'Unknown'
        
        # Ensure all accounts show up even with 0 keys
        for normalized_id in normalized_accounts.keys():
            if normalized_id not in normalized_stats:
                normalized_stats[normalized_id] = 0
        
        report.append("OVERALL STATISTICS")
        report.append("-" * 40)
        report.append(f"Total access keys found: {total_keys}")
        report.append(f"Active keys: {active_keys}")
        report.append(f"Inactive keys: {inactive_keys}")
        report.append(f"High-risk keys (score ≥ 5): {len(high_risk_keys)}")
        report.append("")
        report.append("ACCESS KEYS BY ACCOUNT:")
        for account_id, count in sorted(normalized_stats.items()):
            account_name = normalized_accounts.get(account_id, 'Unknown')
            report.append(f"  {account_id} ({account_name}): {count} keys")
        report.append("")
        
        if high_risk_keys:
            report.append("HIGH-RISK ACCESS KEYS (Score ≥ 5)")
            report.append("-" * 40)
            for key in high_risk_keys:
                account_name = normalized_accounts.get(key.account_id, 'Unknown')
                report.append(f"• {key.username} ({key.key_id}) - Account: {key.account_id} ({account_name}) - Risk Score: {key.risk_score}")
            report.append("")
        
        report.append("DETAILED FINDINGS")
        report.append("-" * 40)
        
        for i, key in enumerate(sorted_keys, 1):
            account_name = normalized_accounts.get(key.account_id, 'Unknown')
            report.append(f"{i}. User: {key.username}")
            report.append(f"   Account: {key.account_id} ({account_name})")
            report.append(f"   Key ID: {key.key_id}")
            report.append(f"   Status: {key.status}")
            report.append(f"   Created: {key.created or 'Unknown'}")
            report.append(f"   Last Used: {key.last_used or 'Never'}")
            report.append(f"   Risk Score: {key.risk_score}/10")
            
            if key.risk_factors:
                report.append("   Risk Factors:")
                for factor in key.risk_factors:
                    report.append(f"     - {factor}")
            
            if key.managed_policies:
                report.append(f"   Managed Policies: {', '.join(key.managed_policies)}")
            
            if key.inline_policies:
                report.append(f"   Inline Policies: {', '.join(key.inline_policies)}")
            
            report.append(f"   Console Access: {'Yes' if key.has_console_access else 'No'}")
            report.append(f"   MFA Enabled: {'Yes' if key.has_mfa else 'No'}")
            report.append("")
        
        return "\n".join(report)

    def run_complete_assessment(self):
        """Run the complete assessment - gather data and analyze"""
        logger.info("Starting complete IAM assessment...")
        
        try:
            # Phase 1: Gather data
            self.gather_all_data()
            
            # Phase 2: Analyze data
            logger.info("=== Starting risk analysis ===")
            self.load_accounts_from_data()
            self.load_access_keys_from_data()
            self.enrich_with_console_access_from_data()
            self.enrich_with_mfa_status_from_data()
            self.enrich_with_policies_from_data()
            self.calculate_risk_scores()
            
            report = self.generate_report()
            
            # Save report to file
            report_file = self.assessment_dir / f"iam_complete_assessment_report_{self.timestamp}.txt"
            with open(report_file, 'w') as f:
                f.write(report)
            
            # Generate CSV reports
            detailed_csv, summary_csv = self.generate_csv_reports()
            
            # Save CloudTrail events
            self.save_all_cloudtrail_events()
            
            logger.info("=" * 60)
            logger.info("COMPLETE IAM ASSESSMENT FINISHED")
            logger.info(f"Gathered data directory: {self.output_dir.absolute()}")
            logger.info(f"Assessment output directory: {self.assessment_dir.absolute()}")
            logger.info(f"Text report: {report_file}")
            logger.info(f"Detailed CSV: {detailed_csv}")
            logger.info(f"Summary CSV: {summary_csv}")
            logger.info("=" * 60)
            
            print(report)
            
        except Exception as e:
            logger.error(f"Error during complete assessment: {e}")
            raise

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Complete IAM assessment tool - gather data and analyze risks'
    )
    parser.add_argument(
        '--profile',
        help='AWS profile name(s) to use (optional). Can specify multiple profiles separated by commas',
        default=None
    )
    
    args = parser.parse_args()
    
    try:
        if args.profile and ',' in args.profile:
            # Multiple profiles - use shared timestamp
            profiles = [p.strip() for p in args.profile.split(',') if p.strip()]
            shared_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            logger.info(f"Running assessment for {len(profiles)} profiles: {profiles}")
            
            all_access_keys = []
            all_accounts = {}
            all_cloudtrail_events = []
            all_gathered_data = {
                'accounts': [],
                'access_keys': [],
                'console_login': [],
                'mfa': [],
                'user_policies': [],
                'user_inline': [],
                'group_policies': [],
                'group_inline': []
            }
            
            for profile in profiles:
                logger.info(f"\n{'='*60}")
                logger.info(f"Starting assessment for profile: {profile}")
                logger.info(f"{'='*60}")
                
                try:
                    assessment = IAMCompleteAssessment(profile_name=profile, shared_timestamp=shared_timestamp, skip_file_writing=True)
                    assessment.gather_all_data()
                    assessment.load_accounts_from_data()
                    assessment.load_access_keys_from_data()
                    assessment.enrich_with_console_access_from_data()
                    assessment.enrich_with_mfa_status_from_data()
                    assessment.enrich_with_policies_from_data()
                    assessment.calculate_risk_scores()
                    
                    # Collect data from this profile
                    all_access_keys.extend(assessment.access_keys)
                    all_accounts.update(assessment.accounts)
                    all_cloudtrail_events.extend(assessment.cloudtrail_events)
                    
                    # Collect gathered data for consolidated files
                    for key in all_gathered_data.keys():
                        all_gathered_data[key].extend(assessment.gathered_data[key])
                    
                    logger.info(f"Completed assessment for profile: {profile}")
                    
                except Exception as e:
                    logger.error(f"Failed to assess profile '{profile}': {e}")
                    logger.warning(f"Skipping profile '{profile}' and continuing with remaining profiles...")
                    continue
            
            # Generate consolidated report
            logger.info(f"\n{'='*60}")
            logger.info("Generating consolidated report and data files for all profiles")
            logger.info(f"{'='*60}")
            
            # Create final assessment with consolidated data
            final_assessment = IAMCompleteAssessment(shared_timestamp=shared_timestamp, report_only=True)
            final_assessment.access_keys = all_access_keys
            final_assessment.accounts = all_accounts
            final_assessment.cloudtrail_events = all_cloudtrail_events
            final_assessment.gathered_data = all_gathered_data
            
            # Write consolidated gathered data files
            final_assessment.write_consolidated_csv('AWS-Accounts.csv', all_gathered_data['accounts'], ['AccountID', 'AccountName'])
            final_assessment.write_consolidated_csv('IAMUser-AccessKey.csv', all_gathered_data['access_keys'], ['AccountID', 'UserName', 'UserId', 'Arn', 'KeyId', 'KeyStatus', 'LastTimeUsed', 'CreationTime'])
            final_assessment.write_consolidated_csv('IAMUser-ConsoleLogin.csv', all_gathered_data['console_login'], ['AccountID', 'UserName', 'UserId', 'Arn', 'LastPasswordUsed'])
            final_assessment.write_consolidated_csv('IAMUser-MFA.csv', all_gathered_data['mfa'], ['AccountID', 'UserName', 'UserId', 'Arn', 'MFAserialNumber'])
            final_assessment.write_consolidated_csv('IAMUser-PoliciesSummary.csv', all_gathered_data['user_policies'], ['AccountID', 'UserName', 'UserId', 'Arn', 'InlinePolicy', 'AWSManagedPolicy', 'CustomerManagedPolicy', 'Groups', 'PermissionsBoundary', 'TotalManagedPoliciesAttached'])
            final_assessment.write_consolidated_csv('IAMUser-InlinePoliciesChecks.csv', all_gathered_data['user_inline'], ['AccountID', 'UserName', 'UserId', 'Arn', 'PolicyName', 'DocumentPolicy'])
            final_assessment.write_consolidated_csv('IAMGroup-PoliciesSummary.csv', all_gathered_data['group_policies'], ['AccountID', 'GroupName', 'GroupId', 'Arn', 'InlinePolicy', 'AWSManagedPolicy', 'CustomerManagedPolicy'])
            final_assessment.write_consolidated_csv('IAMGroup-InlinePoliciesChecks.csv', all_gathered_data['group_inline'], ['AccountID', 'GroupName', 'GroupId', 'Arn', 'PolicyName', 'DocumentPolicy'])
            
            # Generate consolidated reports
            report = final_assessment.generate_report()
            report_file = final_assessment.assessment_dir / f"iam_complete_assessment_report_{shared_timestamp}.txt"
            with open(report_file, 'w') as f:
                f.write(report)
            
            detailed_csv, summary_csv = final_assessment.generate_csv_reports()
            final_assessment.save_consolidated_cloudtrail_events()
            
            logger.info(f"Consolidated assessment completed")
            logger.info(f"Text report: {report_file}")
            logger.info(f"Detailed CSV: {detailed_csv}")
            logger.info(f"Summary CSV: {summary_csv}")
            
            print(report)
        else:
            # Single profile or default credentials
            assessment = IAMCompleteAssessment(profile_name=args.profile)
            assessment.run_complete_assessment()
        
        return 0
    except Exception as e:
        logger.error(f"Complete assessment failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())