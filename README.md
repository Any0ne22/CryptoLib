# CryptoLib  
## EN:
CryptoLib is a simple to use and multi-language cryptographic library.
The purpose of this library is to allow developers to cipher and decipher datas as simple as possible. With CryptoLib it is easy for  the developers to implement strong and secured cryptographic algorithms without an important knowledge on cryptography.


## FR:
CryptoLib est une bibliothèque de cryptographie multi-langages.
Le but de cette bibliothèque est de pouvoir chiffrer et déchiffrer des données le plus simplement possible afin de faciliter l'implémentation d'algorithmes de chiffrement de haute sécurité à des développeurs n'ayant que des connaissances basiques en cryptographie.  

CryptoLib est disponible dans plusieurs languages (C#, Java) et la syntaxe des objets est quasiment identique (mêmes méthodes/types/paramètres) afin de faciliter le passage d'un language à un autre (Les clefs peuvent être générées dans un language, exportées puis importées dans un autre language).  

La documentation détaillée de CryptoLib est disponible sur le [wiki](https://github.com/Any0ne22/CryptoLib/wiki).

CryptoLib v1.0 implèmente les algorithmes suivants:  
-AES ([CryptoAES](https://github.com/Any0ne22/CryptoLib/wiki/(Fr)CryptoAES))  
-RSA ([CryptoRSA](https://github.com/Any0ne22/CryptoLib/wiki/(Fr)CryptoRSA))  

### Versions:  
-C#: v1.0  
-Java: v1.0


# Examples  

## CryptoAES C#

> This example shows how to secure data with CryptoLib using AES algorithm in C#.

`CryptoAES crypto = new CryptoAES("password");`  
`string cipheredData = crypto.EncryptString("some clear text");`  
`string decipheredData = crypto.DecryptString(cipheredData);`  

## CryptoAES Java

> This example shows how to secure data with CryptoLib using AES algorithm in Java.

`CryptoLib.CryptoAES crypto = new CryptoAES("password");`  
`String cipheredData = crypto.EncryptString("some clear text");`  
`String decipheredData = crypto.DecryptString(cipheredData);`  

## CryptoRSA C#

> This example shows how to secure a data transfer between two users (user1 and user2) with CryptoLib using RSA algorithm in C#.

`CryptoRSA user1 = new CryptoRSA(2048);`  
`string user1PublicKey= user1.ExportPublicKeyString();`  

`CryptoRSA user2 = new CryptoRSA();`  
`user2.ImportPublicKeyString(user1PublicKey);`  
`string cipheredData = user2.EncryptString("some clear text");`  

`string decipheredData = user1.DecryptString(cipheredData);`  

## CryptoRSA Java

> This example shows how to secure a data transfer between two users (user1 and user2) with CryptoLib using RSA algorithm in Java.

`CryptoLib.CryptoRSA user1 = new CryptoRSA(2048);`  
`String user1PublicKey= user1.ExportPublicKeyString();`  

`CryptoLib.CryptoRSA user2 = new CryptoRSA();`  
`user2.ImportPublicKeyString(user1PublicKey);`  
`String cipheredData = user2.EncryptString("some clear text");`  

`String decipheredData = user1.DecryptString(cipheredData);`  
