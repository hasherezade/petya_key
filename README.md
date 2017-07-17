# petya_key_poc
A PoC demonstrating that the private key for Petya published by Janus is legitimate.<br/>
</hr>
The Salsa key decoder supports for now only the Red Petya<br/>
Vicitm's data must be decoded from Base58, i.e. using the following decoder:</br>
https://gist.github.com/hasherezade/13e17047a4415fc5ef190fb6db3fe9a2</br>
For the Red Petya, the first two characters of base58 string has to be ommitted.</br>
