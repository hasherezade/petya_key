# petya_key
A decoder for Petya victim keys, using the Janus' masterkey</br>
It supports:
+ Red Petya
+ Green Petya (both versions) + Mischa
+ Goldeneye (bootlocker + files)
</br>
Read more about identifying Petyas: https://blog.malwarebytes.com/cybercrime/2017/07/keeping-up-with-the-petyas-demystifying-the-malware-family/
<hr/>
<b>
DISCLAIMER: Those tools are provided as is and you are using them at your own risk. I am not responsible for any damage or lost data.
</b>
<hr/>
Usage:
<pre>
./petya_key [victim_data]
</pre>
where the 'victim_data' is a file containing the 'personal decryption code' displayed by the bootlocker</br></br>
1) Save your 'personal decryption code' as a continuous string, without separators. Example of the valid file content:
<pre>
e2NKAXKGX7YFYUHPUuwrcfZ6FUkkYtRUdvzqRUwacPgjMvyYr8mH5Pw4X8Wdt6XgLrK7G7m1TVVeBdVzRDayyHFWp76353A1
</pre><br/>
2) Supply the saved file to the decoder:<br/>
<pre>
./petya_key saved_id.txt
</pre>
Choose your version of Petya from the menu. If the given data is valid, you will get your key, i.e:
<pre>
[+] Your key   : TxgTCXnpUPSeR2U7
</pre>
3) <b>Before unlocking attempt I strongly recommend you to make a dump of the full disk.</b> Some versions of Petya are buggy. For example they may hang during decryption and corrupt your data.
<hr/>
In order to decrypt MFT, supply the generated key to the bootlocker.<br/>
In order to decrypt <b>files</b> you need supply the key to an appropriate decryption tool.<br/>
For <b>Mischa</b>:
https://github.com/hasherezade/petya_key/files/7348787/mischa_decrypter.zip
<br/>
For <b>Goldeneye</b>:
https://github.com/hasherezade/petya_key/files/7348772/golden_decrypter.zip
