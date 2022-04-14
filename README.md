# petya_key
A decoder for Petya victim keys, using the Janus' masterkey</br>
It supports:
+ Red Petya
+ Green Petya (both versions) + Mischa
+ Goldeneye (bootlocker + files)

Read more about identifying Petya versions [here](https://blog.malwarebytes.com/cybercrime/2017/07/keeping-up-with-the-petyas-demystifying-the-malware-family/)

[⏬ Download tools](https://github.com/hasherezade/petya_key/releases)

---

*DISCLAIMER: Those tools are provided as is and you are using them at your own risk. I am not responsible for any damage or lost data.*

---
Usage:
```
./petya_key [victim_data]
```
where the `[victim_data]` is a file containing the 'personal decryption code' displayed by the bootlocker

1) Save your _"Personal decryption code"_ as a continuous string, without separators. Example of the valid file content:
```
e2NKAXKGX7YFYUHPUuwrcfZ6FUkkYtRUdvzqRUwacPgjMvyYr8mH5Pw4X8Wdt6XgLrK7G7m1TVVeBdVzRDayyHFWp76353A1
```

2) Supply the saved file to the decoder:
```
./petya_key saved_id.txt
```

Choose your version of Petya from the menu. If the given data is valid, you will get your key, i.e:
```
[+] Your key   : TxgTCXnpUPSeR2U7
```

3) **Before unlocking attempt I strongly recommend you to make a dump of the full disk.** Some versions of Petya are buggy. For example they may hang during decryption and corrupt your data.
---

In order to decrypt MFT, supply the generated key to the bootlocker.<br/>
In order to decrypt **files** you need supply the key to an appropriate decryption tool.

+ For **Mischa**: https://github.com/hasherezade/petya_key/files/7348787/mischa_decrypter.zip
+ For **Goldeneye**: https://github.com/hasherezade/petya_key/files/7348772/golden_decrypter.zip
