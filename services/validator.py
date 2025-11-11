import re
from urllib.parse import urlparse

async def is_working_url(url: str) -> bool:
    url_pattern = re.compile(
        r'^(?:https?://|www\.)'  # начинается с http://, https:// или www.
        r'[\w\-]+(\.[\w\-]+)+'  # доменное имя с точками
        r'([\w\-\.,@?^=%&:/~+#]*[\w\-\@?^=%&/~+#])?$',  # путь, параметры, хэши
        re.IGNORECASE
    )
    return bool(url_pattern.match(url))
