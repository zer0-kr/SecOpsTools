import boto3

def get_instance_ids(session, region):
    ec2_resource = session.resource('ec2', region_name=region)
    return [instance.id for instance in ec2_resource.instances.all()]

def check_and_update_imds_version(ec2_client, instance_id_list):
    vuln_instances = []

    for instance_id in instance_id_list:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        imds_version = response['Reservations'][0]['Instances'][0]['MetadataOptions']['HttpTokens']

        if imds_version == 'optional':
            vuln_instances.append(instance_id)
            print(f'{instance_id} is using IMDS v1. It\'s vulnerable')

    for vuln_instance_id in vuln_instances:
        ec2_client.modify_instance_metadata_options(InstanceId=vuln_instance_id, HttpTokens='required')
        print(f'{vuln_instance_id} set to use IMDS v2')

def main():
    profile = '[profile_name]'
    region = 'ap-northeast-2'

    session = boto3.Session(profile_name=profile)
    ec2_client = session.client('ec2', region_name=region)

    instance_ids = get_instance_ids(session, region)
    check_and_update_imds_version(ec2_client, instance_ids)

if __name__ == "__main__":
    main()
