---
tags:
  - Crypto
  - cheatsheet
---

# برگه تقلب

راهنمای فشرده‌ای شامل تکه‌کدها و اطلاعات کلیدی برای مرور سریع مفاهیم و الگوریتم‌های پرکاربرد رمزنگاری. مناسب برای افراد با دانش قبلی در این حوزه

---


<div dir="ltr" markdown="1">


## Hash
- [Comparison of cryptographic hash functions](https://en.wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions)
- [List of hash functions](https://en.wikipedia.org/wiki/List_of_hash_functions)
- [Hash function security summary](https://en.wikipedia.org/wiki/Hash_function_security_summary)
- Example hashes ([1](https://hashcat.net/wiki/doku.php?id=example_hashes), [2](https://openwall.info/wiki/john/sample-hashes))

=== "hashlib"
    ```python
    import hashlib
    hashlib.sha1(b'salam').hexdigest()

    print(hashlib.algorithms_available)
    print(hashlib.algorithms_guaranteed)
    # {'sha384', 'shake_128', 'blake2s', 'sha3_224', 'blake2b', 'shake_256', 'sha3_384', 'sha224', 'sha3_256', 'sha3_512', 'sha256', 'sha1', 'sha512', 'md5'}
    ```
=== "Crypto"
    ```python
    from Crypto.Hash import SHA
    SHA.new(b'salam').hexdigest()
    ```

### Identify hash
- https://www.kali.org/tools/hash-identifier
- https://www.tunnelsup.com/hash-analyzer
- https://www.onlinehashcrack.com/hash-identification.php


### [Length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack)

1. If `Hash` is vulnerable (e.g., MD5, SHA-1):
    - Knowing `Hash(message1)` and the **length** of `message1`, you can compute `Hash(message1 ‖ message2)` **without knowing message1**.
2. Problematic when the hash is used as a Message Authentication Code (MAC).
3. Allows attackers to append data (`message2`) and forge valid hashes.

#### Tools
  - [Hash Extender](https://github.com/iagox86/hash_extender)  by Ron Bowes
    ```bash
    ./hash_extender -f sha1 -l 1200 -d "GET FILE: " -a "flag.txt" -s b41bd8ce52b42738175f7d4f32c54077789bf4e7
    ```
  - [hlextend](https://github.com/stephenbradshaw/hlextend): Pure Python hash length extension module
- sample writeup: [TagSeries3](https://ctftime.org/writeup/38949) @ WolvCTF 2024

### Hash collisions
- [Hash collisions and exploitations](https://github.com/corkami/collisions)
- [PHP hash collisions](https://github.com/spaze/hashes)

#### [example](https://github.com/corkami/collisions/blob/master/examples/free/README.md)
```python
from hashlib import md5

a = bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2')
b = bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2')
assert a!=b and md5(a).hexdigest() == md5(b).hexdigest()

a = bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e744f8534c00ffb659c4c8740cc942feb2da115a3f415dcbb8607497386656d7d1f34a42059d78f5a8dd1ef')
b = bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e704f8534c00ffb659c4c8740cc942feb2da115a3f4155cbb8607497386656d7d1f34a42059d78f5a8dd1ef')
assert a!=b and md5(a).hexdigest() == md5(b).hexdigest()

a = b"TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
b = b"TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
assert a!=b and md5(a).hexdigest() == md5(b).hexdigest()

a = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
b = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")
assert a!=b and md5(a).hexdigest() == md5(b).hexdigest()
```


---

</div>


