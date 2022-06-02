def check_spf(s: str) -> bool:
    if s.startswith("v=spf1"):
        return True
    return False


def check_dmarc(s: str):
    if s.startswith("v=DMARC1"):
        return True
    return False
