#!/usr/bin/python
 
import urllib2, sys
import boto
from boto import ec2

def get_ec2_connection():
    return boto.ec2.connect_to_region('us-east-1'
#            ,aws_access_key_id='access_key'
#             ,aws_secret_access_key='secret_key'
            )
 
def get_s3_connection():
    return boto.connect_s3(
#            ,aws_access_key_id='access_key'
#             ,aws_secret_access_key='secret_key'
            )

def find_my_pub_ip():
    '''
    simple python method to return your public IP address using ifconfig.me
    if executed from command line will display IP
 
    '''
    headers = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0)' \
                    + ' Gecko/20100101 Firefox/12.0' }
    ip_add = urllib2.urlopen(urllib2.Request("http://ifconfig.me/ip",None, headers )).read()
    return ip_add.strip()
 
 
def add_ip_in_security_group(sg_name, public_ip, region='ap-southeast-1', port=22):
    conn = ec2.connect_to_region(region_name=region)
    rs = conn.get_all_security_groups(sg_name)
    sg = rs[0]
    print public_ip
    #pub_ip_range = '%s0/24' % pub_ip[:-len(pub_ip.split('.')[-1])]
    try:
        sg.authorize(ip_protocol='tcp', from_port=port, to_port=port,
                    cidr_ip=public_ip+'/32')
    except Exception, e:
        print "boto exception:",e
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

def get_configured_ip_from_s3(conn=None):
    if conn is None :
        conn = get_s3_connection()
    bucket_name='ra-office-infra'
    bucket = conn.get_bucket(bucket_name)
    obj = boto.s3.key.Key(bucket)
    obj.key = 'ra_sg_office_ip'
    return obj.get_contents_as_string().strip()

def set_new_configured_ip_to_s3(pub_ip=None, conn=None):
    if conn is None :
        conn = get_s3_connection()
    bucket_name='ra-office-infra'
    bucket = conn.get_bucket(bucket_name)
    obj = boto.s3.key.Key(bucket)
    obj.key = 'ra_sg_office_ip'
    a = obj.set_contents_from_string(pub_ip)

def change_sec_group(region='ap-southeast-1', sg_name='RADIOactive', port=22):
    pub_ip = find_my_pub_ip()
    configured_pub_ip = get_configured_ip_from_s3()
    print "Current IP:"+pub_ip+" Configured IP:"+configured_pub_ip;
    if pub_ip != configured_pub_ip:
        print "updating sec group"
        add_ip_in_security_group(sg_name, pub_ip, region, port)
        set_new_configured_ip_to_s3(pub_ip)
    else:
        print "Not updating"

if __name__=="__main__":
#    addIPSecurity()
    change_sec_group()
