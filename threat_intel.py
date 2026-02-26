def load_blacklist():
    try:
        with open("blacklist.txt", "r") as f:
            return f.read().splitlines()
    except:
        return []