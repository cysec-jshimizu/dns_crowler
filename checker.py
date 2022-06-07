import re

import dns


class check_result:
    policy = ""
    existance = False


def check_spf(record: str) -> check_result:
    result = check_result()

    if not record.startswith("v=spf1"):
        result.existance = False
        return result
    ip_list = record[7:].split(" ")
    policies = []
    for ip in ip_list:
        redirect = re.findall(r"redirect=(\w.+)", ip)
        include_spf = re.findall(r"include:(\w.+)", ip)
        if redirect:
            redirect_records = dns.txt_record(redirect[0])
            for r in redirect_records:
                return check_spf(r)
        elif include_spf:
            include_records = dns.txt_record(include_spf[0])
            for r in include_records:
                try:
                    included_spf_status = check_spf(r)
                except:
                    included_spf_status.policy = "0invalid"
                if included_spf_status.policy != "":
                    policies.append(included_spf_status.policy)

    result.existance = True
    if "-all" in ip_list:
        policies.append("4strict")
    elif "~all" in ip_list:
        policies.append("3relax")
    elif "?all" in ip_list:
        policies.append("2neutral")
    elif "+all" in ip_list:
        policies.append("1pass")

    if len(policies) > 0:
        result.policy = sorted(policies)[0]
    return result


def check_dmarc(record: str) -> check_result:
    result = check_result()

    TAG_NAMES = ["v", "pct", "ruf", "rua", "p", "sp", "fo", "rf", "ri", "adkim", "aspf"]
    record_dict = {}
    if record[-1] == ";":
        record = record[:-1]

    for i in re.split(r";\s?", record):
        splitted = i.split("=", maxsplit=1)
        if splitted[0] not in TAG_NAMES:
            # using invalid tag name
            result.existance = False
            return result

        record_dict[splitted[0]] = splitted[1]

    if record_dict["v"] != "DMARC1":
        result.existance = False
        return result

    # check policy
    if record_dict["p"] == "reject":
        result.policy = "strict"
    elif record_dict["p"] == "quarantine":
        result.policy = "relax"
    elif record_dict["p"] == "none":
        result.policy = "none"
    else:
        result.existance = False
        return result

    result.existance = True
    return result
