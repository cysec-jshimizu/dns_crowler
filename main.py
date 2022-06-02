import checker
import dns


def has_spf(domain: str) -> checker.check_result:
    record = dns.get_record(domain)
    result = checker.check_result()
    for r in record:
        result = checker.check_spf(r["data"])
        if result.existance:
            return result
    return result


def has_dmarc(domain: str) -> checker.check_result:
    record = dns.get_record("_dmarc." + domain)
    result = checker.check_result()
    for r in record:
        result = checker.check_dmarc(r["data"])
        if result.existance:
            return result
    return result


RESULT_FORMAT = "{domain}\tSPF: {spf}({spf_policy})\tDMARC: {dmarc}({dmarc_policy})\n"
with open("./domain_list.txt", "r") as f:
    domains = f.read().splitlines()

data = ""
for domain in domains:
    spf_result = has_spf(domain)
    dmarc_result = has_dmarc(domain)
    data += RESULT_FORMAT.format(
        domain=domain,
        spf=spf_result.existance,
        spf_policy=spf_result.policy,
        dmarc=dmarc_result.existance,
        dmarc_policy=dmarc_result.policy
    )
    with open("./temp.txt", "w") as f:
        f.write(data)
