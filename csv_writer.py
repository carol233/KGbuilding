# coding:utf-8

import os
import csv

csv_folder = "csv"
if not os.path.exists(csv_folder):
    os.mkdir(csv_folder)

file_header = ['id:ID', 'name', 'file_md5', 'safety']
family_header = ['id:ID', 'name']
developer_header = ['id:ID', 'dn', 'md5', 'sha1', 'sha256']
apk_header = ['id:ID', 'name', 'sha256', 'safety', 'min_sdk_version', 'target_sdk_version', 'time',
              'package', 'permissions', 'declared_permissions', 'apk_version', 'receivers', 'services',
              'activities', 'libraries']
domain_header = ['id:ID', 'name', 'safety']
url_header = ['id:ID', 'name', 'safety']
ip_header = ['id:ID', 'name', 'safety']
relation_header = [':START_ID', ':END_ID']

apk_out = open('csv/apk_node.csv', 'w', newline='', encoding='utf-8')
apk_csv_write = csv.writer(apk_out)
apk_csv_write.writerow(apk_header)

file_out = open('csv/file_node.csv', 'w', newline='', encoding='utf-8')
file_csv_write = csv.writer(file_out)
file_csv_write.writerow(file_header)

family_out = open('csv/family_node.csv', 'w', newline='', encoding='utf-8')
family_csv_write = csv.writer(family_out)
family_csv_write.writerow(family_header)

developer_out = open('csv/developer_node.csv', 'w', newline='', encoding='utf-8')
developer_csv_write = csv.writer(developer_out)
developer_csv_write.writerow(developer_header)

domain_out = open('csv/domain_node.csv', 'w', newline='', encoding='utf-8')
domain_csv_write = csv.writer(domain_out)
domain_csv_write.writerow(domain_header)

ip_out = open('csv/ip_node.csv', 'w', newline='', encoding='utf-8')
ip_csv_write = csv.writer(ip_out)
ip_csv_write.writerow(ip_header)

url_out = open('csv/url_node.csv', 'w', newline='', encoding='utf-8')
url_csv_write = csv.writer(url_out)
url_csv_write.writerow(url_header)

apk2file_out = open('csv/apk2file_relation.csv', 'w', newline='', encoding='utf-8')
apk2file_csv_write = csv.writer(apk2file_out)
apk2file_csv_write.writerow(relation_header)

apk2domain_out = open('csv/apk2domain_relation.csv', 'w', newline='', encoding='utf-8')
apk2domain_csv_write = csv.writer(apk2domain_out)
apk2domain_csv_write.writerow(relation_header)

apk2url_out = open('csv/apk2url_relation.csv', 'w', newline='', encoding='utf-8')
apk2url_csv_write = csv.writer(apk2url_out)
apk2url_csv_write.writerow(relation_header)

apk2ip_out = open('csv/apk2ip_relation.csv', 'w', newline='', encoding='utf-8')
apk2ip_csv_write = csv.writer(apk2ip_out)
apk2ip_csv_write.writerow(relation_header)

apk2family_out = open('csv/apk2family_relation.csv', 'w', newline='', encoding='utf-8')
apk2family_csv_write = csv.writer(apk2family_out)
apk2family_csv_write.writerow(relation_header)

apk2developer_out = open('csv/apk2developer_relation.csv', 'w', newline='', encoding='utf-8')
apk2developer_csv_write = csv.writer(apk2developer_out)
apk2developer_csv_write.writerow(relation_header)