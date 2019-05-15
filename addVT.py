# coding:utf-8
# coding:utf-8
import os
import csv
import json

vt_files = "result_data/file_vt_results"
vt_domain = "result_data/domain_results"
vt_ip = "result_data/ip_results"
newcsv = "newcsv"
oldcsv = "csv"

def update_csv(path):
    input = os.path.join(oldcsv, path)
    output = os.path.join(newcsv, path)
    reader = csv.reader(open(input, "r", encoding='utf-8'))
    writer = csv.writer(open(output, 'w', newline='', encoding='utf-8'))
    for line in reader:
        if reader.line_num == 1:
            line.append("info")
            writer.writerow(line)
        else:
            if "domain" in path:
                name = str(line[1])
                vt_file = os.path.join(vt_domain, name + ".txt")
                if not os.path.exists(vt_file):
                    line[-1] = "Unknown"
                    line.append("None")
                else:
                    safety = "safe"
                    info = ""
                    vt_check = json.load(open(vt_file, encoding='utf-8'))

                    if 'Forcepoint ThreatSeeker category' in vt_check:
                        info = info + vt_check['Forcepoint ThreatSeeker category'] + ";"
                    elif 'Dr.Web category' in vt_check:
                        info = info + vt_check['Dr.Web category'] + ";"
                    elif 'BitDefender category' in vt_check:
                        info = info + vt_check['BitDefender category'] + ";"
                    elif 'TrendMicro category' in vt_check:
                        info = info + vt_check['TrendMicro category'] + ";"

                    if 'Malwarebytes hpHosts info' in vt_check:
                        info = info + vt_check['Malwarebytes hpHosts info'] + ";"

                    if 'detected_referrer_samples' in vt_check:
                        if vt_check['detected_referrer_samples'] != []:
                            safety = 'malicious'
                    elif 'detected_downloaded_samples' in vt_check:
                        if vt_check['detected_downloaded_samples'] != []:
                            safety = 'malicious'
                    elif 'detected_urls' in vt_check:
                        if vt_check['detected_urls'] != []:
                            safety = 'malicious'

                    line[-1] = safety
                    line.append(info)

                writer.writerow(line)

            elif "ip" in path:
                name = str(line[1])
                vt_file = os.path.join(vt_ip, name + ".txt")
                if not os.path.exists(vt_file):
                    line[-1] = "Unknown"
                    line.append("None")
                else:
                    safety = "safe"
                    info = ""
                    vt_check = json.load(open(vt_file, encoding='utf-8'))

                    if 'as_owner' in vt_check:
                        info = info + vt_check['as_owner'] + ";"
                    if 'country' in vt_check:
                        info = info + vt_check['country'] + ";"
                    if 'Malwarebytes hpHosts info' in vt_check:
                        info = info + vt_check['Malwarebytes hpHosts info'] + ";"

                    if 'detected_referrer_samples' in vt_check:
                        if vt_check['detected_referrer_samples'] != []:
                            safety = 'malicious'
                    elif 'detected_downloaded_samples' in vt_check:
                        if vt_check['detected_downloaded_samples'] != []:
                            safety = 'malicious'
                    elif 'detected_urls' in vt_check:
                        if vt_check['detected_urls'] != []:
                            safety = 'malicious'

                    line[-1] = safety
                    line.append(info)

                writer.writerow(line)

            elif "file" in path:
                name = str(line[2])
                vt_file = os.path.join(vt_files, name + ".txt")
                if not os.path.exists(vt_file):
                    line[-1] = "Unknown"
                    line.append("None")
                else:
                    safety = "safe"
                    vt_check = json.load(open(vt_file, encoding='utf-8'))

                    if vt_check['positives'] > 0:
                        safety = "malicious"

                    info = "total:" + vt_check['total'] + ";positives:" + vt_check['positives'] + ";"

                    line[-1] = safety
                    line.append(info)

                writer.writerow(line)



if __name__ == '__main__':
    print("Add VT results!")

    if not os.path.exists(newcsv):
        os.mkdir(newcsv)

    # update_csv("apk_node.csv")
    #update_csv("domain_node.csv")
    #update_csv("ip_node.csv")
    update_csv("file_node.csv")

