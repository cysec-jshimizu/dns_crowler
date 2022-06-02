import requests


def get_record(domain: str) -> list:
    doh_url = "https://dns.google.com/resolve?name={}&type=txt"
    res = requests.get(doh_url.format(domain))
    ans = []
    try:
        if res.ok:
            res_j = res.json()
            if "Answer" not in res_j:
                # no record
                return []
            for i in res_j["Answer"]:
                ans.append(i)
            return ans
        else:
            raise Exception("Failed to get record for" + domain)
    except Exception as e:
        print(e)

