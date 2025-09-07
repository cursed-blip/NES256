# NES256

**NES256 (New Encryption Standard 256)** is an educational, AES-inspired block cipher crafted for learning, experimentation, and small-scale applications. It features a 256-bit key, 128-bit block size, and AES-style rounds with SubBytes, ShiftRows, and MixColumns transformations, providing strong diffusion and confusion characteristics.

NES256 uses **CTR mode** for encryption combined with **HMAC-SHA256** for authentication, demonstrating modern principles of authenticated encryption in a compact and approachable implementation. While NES256 is suitable for educational purposes and small business projects, it is not formally audited for high-security environments, so it should **not** be relied upon for sensitive or high-value data.

## How to Use

NES256 comes with a command-line interface through `nes_256_client.py`.

### Encrypt a message:
```
nes_256_client.py encrypt -k <base64_key> -m "Your message here"
```

### Encrypt a file:
```
nes_256_client.py encrypt -k <base64_key> -f path/to/file
```

### Decrypt a message:
```
nes_256_client.py decrypt -k <base64_key> -m "Encrypted message here"
```

### Decrypt a file:
```
nes_256_client.py decrypt -k <base64_key> -f path/to/encrypted_file
```

Replace `<base64_key>` with your 32-byte key encoded in Base64.

I will update this probably if it gets some stars and etc..
If needed help with anything dm @closetcheater67 on discord!
