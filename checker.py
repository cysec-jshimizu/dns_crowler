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
    for ip in ip_list:
        redirect = re.findall(r"redirect=(\w.+)", ip)
        if redirect:
            r2 = dns.dig_record(redirect[0])
            for r in r2:
                return check_spf(r)

    result.existance = True
    if "-all" in ip_list:
        result.policy = "strict"
    elif "~all" in ip_list:
        result.policy = "relax"
    elif "?all" in ip_list:
        result.policy = "newtral"
    elif "+all" in ip_list:
        result.policy = "pass"

    return result


def check_dmarc(record: str) -> check_result:
    result = check_result()

    TAG_NAMES = ["v", "pct", "ruf", "rua", "p", "sp", "fo", "rf", "ri", "adkim", "aspf"]
    record_dict = {}
    if record[-1] == ";":
        record = record[:-1]

    for i in re.split(r";\s?", record):
        temp = i.split("=", maxsplit=1)
        if temp[0] not in TAG_NAMES:
            # using invalid tag name
            result.existance = False
            return result

        record_dict[temp[0]] = temp[1]

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


if __name__ == "__main__":
    print(check_spf("v=spf1 redirect=_spf.mail.ru").policy)
    print(check_spf("v=spf1 include:_spf.google.com ~all"))
    print(check_dmarc("v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"))
