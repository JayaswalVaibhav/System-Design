import hashlib


def url_shortner(url):
    """
    :param url: long url
    :return: MD5 hash on the url and take first 7 digits
    """
    digits = 7
    result = hashlib.md5(url.encode())
    return result.hexdigest()[:digits]
