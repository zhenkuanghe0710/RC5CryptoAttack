For the RC5 algorithm, the program files are: 
RC5.java and BlockCipher.java. 

The usage of RC5.java is as follows:

java RC5 <Type> <PlainText/CipherText> <Key> <Round>

where:

<Type> 
= 1 Character String of 1 (Encryption) or 2 (Decryption)

<PlainText/CipherText> 
= 16 Character Hex String
Type = 1 input PlainText; Type = 2 input CipherText

<Key> 
= 32 Charater Hex Key String

<Round> 
= Number of Rounds

For the One round RC5 Attack program, the program files are: 
AttackRC5.java, RC5.java, and BlockCipher.java. 

The usage of AttackRC5.java is as follows:

java AttackRC5 <Key>

where:

<Key> 
= 32 Character Hex Key String