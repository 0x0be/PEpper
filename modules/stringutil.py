import string

# the "strings" utility written in Python


def get(filename, min=4):
    try:
        with open(filename, "rb") as f:
            result = ""
            for c in f.read():
                if c in string.printable:
                    result += c
                    continue
                if len(result) >= min:
                    yield result
                result = ""
            if len(result) >= min:
                yield result

    except Exception as e:
        print(e)
