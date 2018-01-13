# EZcipher  
## EN:
EZcipher is a user-friendly and multi-language cryptographic library.
The purpose of this library is to allow developers to cipher and decipher data as simple as possible. With EZcipher it is easy for  the developers to implement strong and secured cryptographic algorithms without an important knowledge of cryptography.  

EZcipher is available in multiples languages (C#, Java) and the syntax is practically the same (same objects/types/methods) to facilitate the passing from a language to another (keys can be generated in a language, exported then imported in another language).  

The detailed documentation is available on the [wiki](https://github.com/Any0ne22/EZcipher/wiki).

EZcipher v1.1 implements the following algorithms:  
-AES ([CryptoAES](https://github.com/Any0ne22/EZcipher/wiki/(Fr)CryptoAES))  
-RSA ([CryptoRSA](https://github.com/Any0ne22/EZcipher/wiki/(Fr)CryptoRSA))  
-PBKDF2 key derivation algorithm ([CryptoDeriveBytes](https://github.com/Any0ne22/EZcipher/wiki/(Fr)CryptoDeriveBytes))  


## FR:
EZcipher est une bibliothèque de cryptographie multi-langages.
Le but de cette bibliothèque est de pouvoir chiffrer et déchiffrer des données le plus simplement possible afin de faciliter l'implémentation d'algorithmes de chiffrement de haute sécurité à des développeurs n'ayant que des connaissances basiques en cryptographie.  

EZcipher est disponible dans plusieurs languages (C#, Java) et la syntaxe des objets est quasiment identique (mêmes méthodes/types/paramètres) afin de faciliter le passage d'un language à un autre (Les clefs peuvent être générées dans un language, exportées puis importées dans un autre language).  

La documentation détaillée de EZcipher est disponible sur le [wiki](https://github.com/Any0ne22/EZcipher/wiki).

EZcipher v1.1 implémente les algorithmes suivants:  
-AES ([CryptoAES](https://github.com/Any0ne22/EZcipher/wiki/(Fr)CryptoAES))  
-RSA ([CryptoRSA](https://github.com/Any0ne22/EZcipher/wiki/(Fr)CryptoRSA))  
-L'algorithme de dérivation de clé PBKDF2 ([CryptoDeriveBytes](https://github.com/Any0ne22/EZcipher/wiki/(Fr)CryptoDeriveBytes))  



# Versions:  
-C#: v1.1  
-Java: v1.1


# Examples

## CryptoAES C#

> This example shows how to secure data with EZcipher using AES algorithm in C#.

`CryptoAES crypto = new CryptoAES("password");`  
`string cipheredData = crypto.EncryptString("some clear text");`  
`string decipheredData = crypto.DecryptString(cipheredData);`  

## CryptoAES Java

> This example shows how to secure data with EZcipher using AES algorithm in Java.

`EZcipher.CryptoAES crypto = new CryptoAES("password");`  
`String cipheredData = crypto.EncryptString("some clear text");`  
`String decipheredData = crypto.DecryptString(cipheredData);`  

## CryptoRSA C#

> This example shows how to secure a data transfer between two users (user1 and user2) with EZcipher using RSA algorithm in C#.

`CryptoRSA user1 = new CryptoRSA(2048);`  
`string user1PublicKey = user1.ExportPublicKeyString();`  

`CryptoRSA user2 = new CryptoRSA();`  
`user2.ImportPublicKeyString(user1PublicKey);`  
`string cipheredData = user2.EncryptString("some clear text");`  

`string decipheredData = user1.DecryptString(cipheredData);`  

## CryptoRSA Java

> This example shows how to secure a data transfer between two users (user1 and user2) with EZcipher using RSA algorithm in Java.

`EZcipher.CryptoRSA user1 = new CryptoRSA(2048);`  
`String user1PublicKey = user1.ExportPublicKeyString();`  

`EZcipher.CryptoRSA user2 = new CryptoRSA();`  
`user2.ImportPublicKeyString(user1PublicKey);`  
`String cipheredData = user2.EncryptString("some clear text");`  

`String decipheredData = user1.DecryptString(cipheredData);`  

# ChangeLogs

-Changing repository name from CryptoLib to EZcipher

### V1.1
-Adding class CryptoDeriveBytes  
-The CryptoAES class use the CryptoDeriveBytes to get a derived key from a password  
-Adding ECB cipher mode to CryptoAES  
