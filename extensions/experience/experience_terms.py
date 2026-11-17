"""Small, auditable query aliases; no embeddings, model calls or stored secrets."""
import re
import unicodedata

ALIASES = (
    ("idor", "越权", "authorization", "access control", "权限校验"),
    ("ssrf", "服务端请求伪造", "服务器端请求伪造"),
    ("path traversal", "目录穿越", "路径遍历", "路径穿越"),
    ("file upload", "文件上传", "upload"),
    ("lfi", "本地文件包含", "local file inclusion"),
    ("deserialization", "反序列化", "deserialize"),
    ("ssti", "模板注入", "template injection"),
    ("sqli", "sql injection", "sql注入"),
    ("csrf", "跨站请求伪造"),
    ("race condition", "条件竞争", "竞态"),
    ("jwt", "json web token"),
    ("false positive", "假阳性", "误报", "伪200"),
)


def lexical_tokens(value):
    text = unicodedata.normalize("NFKC", str(value or "")).lower()
    out = re.findall(r"[a-z0-9_+-]{2,}", text)
    for part in re.findall(r"[\u3400-\u9fff]+", text):
        out.extend(part[i:i + 2] for i in range(len(part) - 1))
        if len(part) == 1:
            out.append(part)
    return list(dict.fromkeys(out))[:32]


def search_tokens(value):
    text = unicodedata.normalize("NFKC", str(value or "")).lower()
    out = lexical_tokens(text)
    for group in ALIASES:
        if any((alias in text if re.search(r"[\u3400-\u9fff]", alias)
                else re.search(r"(?<![a-z0-9_])" + re.escape(alias) + r"(?![a-z0-9_])", text)) for alias in group):
            out.extend(group)
    return list(dict.fromkeys(out))[:32]
