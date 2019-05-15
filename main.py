# coding:utf-8
import os
import re
import filetypes
from csv_writer import *
import json
import os
import csv

apk2family_csv = {}

def load_family():
    path = "result_data/RmvDroid-Metadata.csv"
    reader = csv.reader(open(path, "r", encoding='utf-8'))
    for line in reader:
        if reader.line_num == 1:
            continue
        malfamily = line[-3]
        file_sha256 = line[-1]
        apk2family_csv[file_sha256] = malfamily
        if malfamily not in family_hash_dic:
            family_id = get_id()
            family_hash_dic[malfamily] = family_id
            family_row = [family_id, malfamily]
            family_csv_write.writerow(family_row)


root_path = "result_data"
file_root_path = os.path.join(root_path, "files_names")
info_root_path = os.path.join(root_path, "info_results")

id = 0
url_hash_dic = {}
domain_hash_dic = {}
ip_hash_dic = {}
file_hash_dic = {}
family_hash_dic = {}
developer_hash_dic = {}


def get_id():
    global id
    id += 1
    return id


def get_file_type(file_path):
    extension = os.path.splitext(file_path)[1].lower().strip('.')
    if extension in filetypes.PICS:
        return "picture"
    elif extension in filetypes.AUDIOS:
        return "audio"
    elif extension in filetypes.VIDEOS:
        return "video"
    else:
        return extension

if __name__ == '__main__':

    load_family()
    print("Family loaded done!")

    for apkname in os.listdir(info_root_path):

        apk_hash = apkname.strip(".json")

        info_json_file = os.path.join(info_root_path, apkname)
        try:
            with open(info_json_file) as stream:
                data = json.loads(stream.read())
        except Exception as e:
            print(e, apkname)
            continue

        if 'en_name' in data['meta']:
            apk_name = data['meta']['en_name'].encode('utf-8')
        elif 'zh_name' in data['meta']:
            apk_name = data['meta']['zh_name'].encode('utf-8')
        else:
            apk_name = "None"

        apk_id = get_id()
        apk_row = [apk_id, apk_name, apk_hash, "safe", data['min_sdk_version'], data['target_sdk_version'],
                    data['date'], data['meta']['package_name'], data['permission'], data['declared_permission'],
                    data['apk_version'], data['receiver'], data['service'], data['activity'], data['library']
                    ]
        apk_csv_write.writerow(apk_row)

        """family"""
        malfamily = apk2family_csv[apk_hash]
        family_id = family_hash_dic[malfamily]
        apk2family_row = [apk_id, family_id]
        apk2family_csv_write.writerow(apk2family_row)

        """developer"""
        signatures = data['sign']
        dn = signatures['dn']
        md5 = signatures['md5']
        sha1 = signatures['sha1']
        sha256 = signatures['sha256']
        # developer_header = ['id:ID', 'dn', 'md5', 'sha1', 'sha256']
        if md5 in developer_hash_dic:
            devel_id = developer_hash_dic[md5]
        else:
            devel_id = get_id()
            developer_hash_dic[md5] = devel_id
            developer_row = [devel_id, dn, md5, sha1, sha256]
            developer_csv_write.writerow(developer_row)

        apk2developer_row = [apk_id, devel_id]
        apk2developer_csv_write.writerow(apk2developer_row)

        """url"""
        urls = []
        for url in data['resource']:
            if re.match(r'(?:https?|ftp):\/\/[\w/\-?=%.]+\.[\w/\-?=%.]+', url):
                urls.append(url.strip())

        urls = list(set(urls))  # apk内去重

        for url in urls:
            if url in url_hash_dic:
                url_id = url_hash_dic[url]
            else:
                url_id = get_id()
                url_hash_dic[url] = url_id
                url_row = [url_id, url, "safe"]
                url_csv_write.writerow(url_row)

            apk2url_row = [apk_id, url_id]
            apk2url_csv_write.writerow(apk2url_row)


        """domain and ip"""
        domains = []
        ips = []
        for item in urls:
            res = re.findall(r'(?:https?|ftp):\/\/((\w+\.)+\w+)', item)
            if res:
                domain = res[0][0]
                if re.match(r'[0-9]+(?:\.[0-9]+){3}', domain):
                    ips.append(domain)
                else:
                    domains.append(domain)
        domains = list(set(domains))
        ips = list(set(ips))

        for domain in domains:
            if domain in domain_hash_dic:
                domain_id = domain_hash_dic[domain]
            else:
                domain_id = get_id()
                domain_hash_dic[domain] = domain_id
                domain_row = [domain_id, domain, "safe"]
                domain_csv_write.writerow(domain_row)
            apk2domain_row = [apk_id, domain_id]
            apk2domain_csv_write.writerow(apk2domain_row)


        for ip in ips:
            if ip in ip_hash_dic:
                ip_id = ip_hash_dic[ip]
            else:
                ip_id = get_id()
                ip_hash_dic[ip] = ip_id
                ip_row = [ip_id, ip, "safe"]
                ip_csv_write.writerow(ip_row)
            apk2ip_row = [apk_id, ip_id]
            apk2ip_csv_write.writerow(apk2ip_row)


        """file"""
        file_info_path = os.path.join(file_root_path, apk_hash, 'hashfile.txt')
        with open(file_info_path, encoding='utf-8') as f:
            lines = f.readlines()

        files = {}
        for line in lines:
            line = line.split(" ")
            file_md5 = line[0]
            file_name = line[1].strip()
            files[file_md5] = file_name

        for file_md5 in files:
            if file_md5 in file_hash_dic:
                file_id = file_hash_dic[file_md5]
            else:
                file_id = get_id()
                file_hash_dic[file_md5] = file_id
                path = files[file_md5]
                file_row = [file_id, path, file_md5, get_file_type(path), "safe"]
                file_csv_write.writerow(file_row)
            apk2file_row = [apk_id, file_id]
            apk2file_csv_write.writerow(apk2file_row)

    fw_id = get_id()
    f = open("last_id.txt", "w")
    f.write(str(fw_id))
    f.close()












