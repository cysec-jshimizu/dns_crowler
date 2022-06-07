import subprocess


def txt_record(domain: str):
    ans = []
    res = subprocess.run(["dig", "+short", domain, "txt"], capture_output=True)
    out = res.stdout.decode("utf-8")
    if res.returncode == 9:
        print("timeout:", domain)
        return ans
    elif res.returncode != 0:
        print(res.returncode, domain)
        exit()

    if len(out) == 0:
        return []
    for i in out[:-1].split("\n"):
        ans.append(i[1:-1])
    return ans


def mx_record(domain: str) -> list:
    ans = []
    res = subprocess.run(["dig", "+short", domain, "mx"], capture_output=True)
    out = res.stdout.decode("utf-8")
    if res.returncode == 9:
        print("timeout:", domain)
        return ans
    elif res.returncode != 0:
        print(res.returncode, domain)
        exit()

    if len(out) == 0:
        return []

    try:
        for record in out[:-1].split("\n"):
            ans.append(record.split(" ")[1][:-1])
    except IndexError:
        return []

    if ans == [""]:
        return []

    return ans
