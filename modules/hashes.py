import hashlib
import os
import sys

# return md5, sha1, sha256 hashes of data argument


def get(data):
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    if os.path.exists(sys.argv[1]):
        with open(data, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
    else:
        print(("No such file or directory named: " + sys.argv[1]))
        sys.exit()

    f.close()
    md5 = md5.hexdigest()
    sha1 = sha1.hexdigest()
    sha256 = sha256.hexdigest()
    return {'md5': md5, 'sha1': sha1, 'sha256': sha256}
