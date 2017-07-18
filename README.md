# petya_key_poc
A decoder for Petya victim keys, using the Janus' masterkey</br>
For now it supports:
+ Red Petya
+ Goldeneye Petya
</br>
Usage:
<pre>
./petya_key_poc [victim_data]
</pre>
where the victim_data is a Victim ID decoded from Base58, i.e. using the following decoder:</br>
https://gist.github.com/hasherezade/13e17047a4415fc5ef190fb6db3fe9a2</br>
For the Red Petya, the first two characters of Base58 string has to be ommitted.</br>
<hr/>
<b>
WARNING: This is an experimental version. Some elements are unfinished.
</b>
