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
where the victim_data is a Victim ID decoded from Base58, i.e. using the following decoder:</br>
base58.py: 
https://gist.github.com/hasherezade/13e17047a4415fc5ef190fb6db3fe9a2</br><br/>
1) Save your Victim ID (without dashes) in a file (i.e. saved_id.txt) and supply it to the script. Example of the valid file content:
<pre>
e2NKAXKGX7YFYUHPUuwrcfZ6FUkkYtRUdvzqRUwacPgjMvyYr8mH5Pw4X8Wdt6XgLrK7G7m1TVVeBdVzRDayyHFWp76353A1
</pre><br/>
2) Convert it from Base58:<br/>
<b>For the Red Petya:</b><br/>the first two characters of Base58 string has to be ommitted.</br>
<pre>
./base58.py --decode --infile saved_id.txt --skip_b 2
</pre>
<b>For the Green Petya:</b><br/>the first two characters and last six characters of Base58 string has to be ommitted.</br>
<pre>
./base58.py --decode --infile saved_id.txt --skip_b 2 --skip_e 6
</pre>
<b>For the Goldeneye Petya:</b><br/>supply the Victim ID as is</br>
<pre>
./base58.py --decode --infile saved_id.txt
</pre>
3) Supply the output file to the decoder:<br/>
<pre>
./petya_key_poc out.tmp
</pre>
Choose your version of Petya from the menu. If the given data is valid, you will get your key, i.e:
<pre>
[+] Your key   : TxgTCXnpUPSeR2U7
</pre>

