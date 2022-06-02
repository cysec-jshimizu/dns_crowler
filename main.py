import requests

import checker


def get_record(domain: str) -> list:
    doh_url = "https://dns.google.com/resolve?name={}&type=txt"
    res = requests.get(doh_url.format(domain))
    ans = []
    try:
        if res.ok:
            res_j = res.json()
            if "Answer" not in res_j:
                raise Exception("no txt record for" + domain)
            for i in res_j["Answer"]:
                ans.append(i)
            return ans
        else:
            raise Exception("Failed to get record for" + domain)
    except Exception as e:
        print(e)
        return []


def has_spf(domain: str) -> bool:
    record = get_record(domain)
    for r in record:
        if checker.check_spf(r["data"]):
            return True
    return False


def has_dmarc(domain: str) -> bool:
    record = get_record("_dmarc." + domain)
    for r in record:
        if checker.check_dmarc(r["data"]):
            return True
    return False


DEBUG = True
if DEBUG:
    domain = "google.com"
    domain = "example.com"

print(has_spf(domain), has_dmarc(domain))
