# petya_key_poc
A decoder for Petya victim keys, using the Janus' masterkey</br>
It supports:
+ Red Petya
+ Green Petya (both versions)
+ Goldeneye Petya
</br>
Read more about identifying Petyas: https://blog.malwarebytes.com/cybercrime/2017/07/keeping-up-with-the-petyas-demystifying-the-malware-family/
<hr/>
<b>
WARNING: This is an experimental version. Some elements are unfinished.
</b>
<hr/>
Usage:
<pre>
./petya_key_poc [victim_data]
</pre>
where the 'victim_data' is a file containing the 'personal decryption code' displayed by the bootlocker</br></br>
1) Save your 'personal decryption code' as a continuous string, without separators. Example of the valid file content:
<pre>
e2NKAXKGX7YFYUHPUuwrcfZ6FUkkYtRUdvzqRUwacPgjMvyYr8mH5Pw4X8Wdt6XgLrK7G7m1TVVeBdVzRDayyHFWp76353A1
</pre><br/>
2) Supply the saved file to the decoder:<br/>
<pre>
./petya_key_poc saved_id.txt
</pre>
Choose your version of Petya from the menu. If the given data is valid, you will get your key, i.e:
<pre>
[+] Your key   : TxgTCXnpUPSeR2U7
</pre>
3) Before unlocking attempt I strongly recommend you to make a dump of the full disks. Some versions of Petya are buggy. For example they may hang during decryption and corrupt your data.
