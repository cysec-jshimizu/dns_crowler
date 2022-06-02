import os


def dig_record(domain: str):
    ans = []
    out = os.popen(f"dig +short {domain} txt").read()
    if len(out) == 0:
        return []
    for i in out[:-1].split("\n"):
        ans.append(i[1:-1])
    return ans
