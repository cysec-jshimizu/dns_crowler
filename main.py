import csv

import checker
import dns


def has_spf(domain: str) -> checker.check_result:
    record = dns.txt_record(domain)
    result = checker.check_result()
    for r in record:
        result = checker.check_spf(r)
        if result.existance:
            return result
    return result


def has_dmarc(domain: str) -> checker.check_result:
    record = dns.txt_record("_dmarc." + domain)
    result = checker.check_result()
    for r in record:
        result = checker.check_dmarc(r)
        if result.existance:
            return result
    return result


arr = []
with open("./localgov_domain.csv", "r") as f:
    reader = csv.reader(f)
    domains = [row for row in reader]


for i, localgov in enumerate(domains):
    if i == 0:
        arr.append(localgov)
        continue

    domain = localgov[3]

    spf_result = has_spf(domain)
    dmarc_result = has_dmarc(domain)
    mx_records = dns.mx_record(domain)
    data = [localgov[0], localgov[1], localgov[2], domain, spf_result.existance,
            spf_result.policy[1:], dmarc_result.existance, dmarc_result.policy]

    if len(mx_records) > 0:
        for mx in mx_records:
            mx_spf_result = has_spf(mx)
            mx_dmarc_result = has_dmarc(mx)
            data = [localgov[0], localgov[1], localgov[2], domain, spf_result.existance,
                    spf_result.policy[1:], dmarc_result.existance,
                    dmarc_result.policy, mx, mx_spf_result.existance, mx_spf_result.policy[1:],
                    mx_dmarc_result.existance, mx_dmarc_result.policy]
            arr.append(data)
    else:
        data.extend(["", "", "", "", ""])
        arr.append(data)

    if i % 30 == 0:
        with open("./mail_sec.csv", "a") as f:
            writer = csv.writer(f)
            writer.writerows(arr)

        arr = []
