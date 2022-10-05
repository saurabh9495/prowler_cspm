from operator import contains
import os
import time
import re
import csv
from tokenize import endpats

header = ['CHECK_ID', 'CHECK_TITLE', 'CHECK_SCORED', 'CHECK_CIS_LEVEL',
          'CHECK_SEVERITY', 'CHECK_ASFF_RESOURCE_TYPE', 'CHECK_ALTERNATE', 'CHECK_ALTERNATE_check', 'CHECK_ASFF_COMPLIANCE_TYPE', 'CHECK_SERVICENAME', 'CHECK_RISK', 'CHECK_REMEDIATION', 'CHECK_DOC', 'CHECK_CAF_EPIC']

header_set = {'check'}

with open('prowler-out.csv', 'w', encoding='UTF8') as f:
    writer = csv.writer(f)

    # write the header
    writer.writerow(header)

    counter = 0

    for root, dirs, files in os.walk('/Users/saurabhkumar/Downloads/started_wifi/prowler_cspm/checks'):

        print("----------------------------------------------------")
        # print(root, dirs, files)

        for file in files:

            data = []
            data_dict = {}
            # print(os.path.join(root, file))
            # os.system('python3 ' + os.path.join(root, file))
            filename = os.path.join(root, file)
            file_ = open(filename, 'r')
            # content = file_.read()
            # print(content)

            # try:
            #     if 'check_extra' in str(filename):
            #         key = str(filename).split('check_extra')[1]
            #     else:
            #         key = str(filename).split('check')[2]
            # except Exception as e:
            #     print(e)
            #     print(os.path.join(root, file))

            # print(key,"was a called")

            line = file_.readline()

            while True:
                line = file_.readline()

                if line == '':
                    break
                # print(line)

                # match_CHECK = re.search(
                #     r"CHECK", line, re.MULTILINE | re.DOTALL)

                # if match_CHECK:
                #     try:
                #         # print(((line.split('=', 1)[0]).replace(str(key), '')).strip())
                #         header_set.add(
                #             ((line.split('=', 1)[0]).replace(str(key), '')).strip())
                #     except Exception as e:
                #         print(e)
                #         header_set.add("NA")

                match_CHECK_ID = re.search(
                    r"CHECK_ID", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_ID:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_ID"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_ID"] = "NA"

                match_CHECK_TITLE = re.search(
                    r"CHECK_TITLE", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_TITLE:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_TITLE"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_TITLE"] = "NA"

                match_CHECK_SCORED = re.search(
                    r"CHECK_SCORED", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_SCORED:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_SCORED"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_SCORED"] = "NA"

                match_CHECK_CIS_LEVEL = re.search(
                    r"CHECK_CIS_LEVEL", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_CIS_LEVEL:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_CIS_LEVEL"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_CIS_LEVEL"] = "NA"

                match_CHECK_SEVERITY = re.search(
                    r"CHECK_SEVERITY", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_SEVERITY:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_SEVERITY"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_SEVERITY"] = "NA"

                match_CHECK_ASFF_RESOURCE_TYPE = re.search(
                    r"CHECK_ASFF_RESOURCE_TYPE", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_ASFF_RESOURCE_TYPE:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_ASFF_RESOURCE_TYPE"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter) +
                                  "CHECK_ASFF_RESOURCE_TYPE"] = "NA"

                match_CHECK_ALTERNATE = re.search(
                    r"CHECK_ALTERNATE", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_ALTERNATE:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_ALTERNATE"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_ALTERNATE"] = "NA"

                match_CHECK_ALTERNATE_check = re.search(
                    r"CHECK_ALTERNATE_check", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_ALTERNATE_check:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_ALTERNATE_check"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_ALTERNATE_check"] = "NA"

                match_CHECK_ASFF_COMPLIANCE_TYPE = re.search(
                    r"CHECK_ASFF_COMPLIANCE_TYPE", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_ASFF_COMPLIANCE_TYPE:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_ASFF_COMPLIANCE_TYPE"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter) +
                                  "CHECK_ASFF_COMPLIANCE_TYPE"] = "NA"

                match_CHECK_SERVICENAME = re.search(
                    r"CHECK_SERVICENAME", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_SERVICENAME:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_SERVICENAME"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter) +
                                  "CHECK_SERVICENAME"] = "NA"

                match_CHECK_RISK = re.search(
                    r"CHECK_RISK", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_RISK:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_RISK"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_RISK"] = "NA"

                match_CHECK_REMEDIATION = re.search(
                    r"CHECK_REMEDIATION", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_REMEDIATION:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_REMEDIATION"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter) +
                                  "CHECK_REMEDIATION"] = "NA"

                match_CHECK_DOC = re.search(
                    r"CHECK_DOC", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_DOC:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_DOC"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_DOC"] = "NA"

                match_CHECK_CAF_EPIC = re.search(
                    r"CHECK_CAF_EPIC", line, re.MULTILINE | re.DOTALL)

                if match_CHECK_CAF_EPIC:
                    try:
                        # print(((line.split('=', 1)[1]).strip())[1:-1])
                        data_dict[str(counter)+"CHECK_CAF_EPIC"] = (
                            ((line.split('=', 1)[1]).strip())[1:-1])
                    except Exception as e:
                        print(e)
                        data_dict[str(counter)+"CHECK_CAF_EPIC"] = "NA"

                # if '(){' in line:
                #     print(line)
                #     # time.sleep(1)
                #     break

            # write the data
            # print(data_dict)
            try:
                data.append(data_dict[str(counter)+"CHECK_ID"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_TITLE"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_SCORED"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_CIS_LEVEL"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_SEVERITY"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(
                    data_dict[str(counter)+"CHECK_ASFF_RESOURCE_TYPE"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_ALTERNATE"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_ALTERNATE_check"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(
                    data_dict[str(counter)+"CHECK_ASFF_COMPLIANCE_TYPE"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_SERVICENAME"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_RISK"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_REMEDIATION"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_DOC"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            try:
                data.append(data_dict[str(counter)+"CHECK_CAF_EPIC"])
            except Exception as e:
                print(os.path.join(root, file))
                data.append("NA")
                print(e)
            writer.writerow(data)
            counter += 1
            file_.close()
            # time.sleep(1)

# print(header_set)
