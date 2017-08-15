/*
CryptoLib v1.1
Made by Tom Gouville
https://github.com/Any0ne22/CryptoLib/
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Numerics;

namespace CryptoLib
{
    public class CryptoAES
    {
        private byte[] key = new byte[32];
        private byte[] iv = new byte[16];
        private CipherMode mode = CipherMode.CBC;

        public CryptoAES(string password = null)
        {
            if(password != null)
                GenerateAlgotihmInputs(password);
        }

        public void setCipherMode(string cipherMode)
        {
        	if(cipherMode == "CBC")
            {
                mode = CipherMode.CBC;
            }
        	else if(cipherMode == "ECB")
            {
                mode = CipherMode.ECB;
            }
        	else
            {
                throw new ArgumentException("Bad cipher mode!");
            }
        }

        public List<byte[]> GenerateAlgotihmInputs(string password, string hmacAlgorithm = null, int derivationIterationsCount = 10000)
        {
            List<byte[]> result = new List<byte[]>();

            CryptoDeriveBytes derivation = new CryptoDeriveBytes();
            if (hmacAlgorithm != null)
                derivation.SetPseudoRandomFunction(hmacAlgorithm);
            byte[] derivedKey = derivation.DerivesBytes(password, Encoding.UTF8.GetBytes(password), derivationIterationsCount, 64);

            Array.Copy(derivedKey, 0, key, 0, 32);
            Array.Copy(derivedKey, 32, iv, 0, 16);

            result.Add(key);
            result.Add(iv);

            return result;
        }

        public string EncryptString(string clearText, byte[] encryptKey = null, byte[] encryptIv = null)
        {
            if (encryptKey == null && encryptIv == null && key != null && iv != null)
            {
                encryptKey = key;
                encryptIv = iv;
            }
            else if ((encryptKey == null || encryptIv == null) && key == null && iv == null)
            {
                throw new System.ArgumentException("Key and initialisation vector are not initialized");
            }


            // Place le texte à chiffrer dans un tableau d'octets
            byte[] plainText = Encoding.UTF8.GetBytes(clearText);


            RijndaelManaged rijndael = new RijndaelManaged();

            // Définit le mode utilisé
            rijndael.Mode = mode;

            // Crée le chiffreur AES - Rijndael
            ICryptoTransform aesEncryptor = rijndael.CreateEncryptor(encryptKey, encryptIv);

            MemoryStream ms = new MemoryStream();

            // Ecris les données chiffrées dans le MemoryStream
            CryptoStream cs = new CryptoStream(ms, aesEncryptor, CryptoStreamMode.Write);
            cs.Write(plainText, 0, plainText.Length);
            cs.FlushFinalBlock();


            // Place les données chiffrées dans un tableau d'octet
            byte[] CipherBytes = ms.ToArray();


            ms.Close();
            cs.Close();

            // Place les données chiffrées dans une chaine encodée en Base64
            return Convert.ToBase64String(CipherBytes);


        }

        public string DecryptString(string cipherText, byte[] encryptKey = null, byte[] encryptIv = null)
        {
            if(encryptKey == null && encryptIv == null && key != null && iv != null)
            {
                encryptKey = key;
                encryptIv = iv;
            }
            else if((encryptKey == null || encryptIv == null) && key == null && iv == null)
            {
                throw new System.ArgumentException("Key and initialisation vector are not initialized");
            }

            byte[] cipheredData = Convert.FromBase64String(cipherText);


            RijndaelManaged rijndael = new RijndaelManaged();
            rijndael.Mode = mode;


            // Ecris les données déchiffrées dans le MemoryStream
            ICryptoTransform decryptor = rijndael.CreateDecryptor(key, iv);
            MemoryStream ms = new MemoryStream(cipheredData);
            CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

            // Place les données déchiffrées dans un tableau d'octet
            byte[] plainTextData = new byte[cipheredData.Length];

            int decryptedByteCount = cs.Read(plainTextData, 0, plainTextData.Length);

            ms.Close();
            cs.Close();

            return Encoding.UTF8.GetString(plainTextData, 0, decryptedByteCount);
        }

    }

    public class CryptoRSA
    {
        private RSACryptoServiceProvider csp = null;

        public CryptoRSA(int keySize = 2048)
        {
            GenerateKeys(keySize);
        }

        public void GenerateKeys(int keySize = 2048)
        {
            csp = new RSACryptoServiceProvider(keySize);

            RSAParameters clePrive = csp.ExportParameters(true);
            RSAParameters clePublique = csp.ExportParameters(false);
        }

        public string EncryptString(string clearText)
        {
            if(csp == null)
            {
                throw new System.ArgumentException("No keys generated!");
            }
            
            byte[] byteDataToEncrypt = System.Text.Encoding.UTF8.GetBytes(clearText);
            byte[] byteEncriptedData = csp.Encrypt(byteDataToEncrypt, false);
            string plainTextCipheredData = Convert.ToBase64String(byteEncriptedData);

            return plainTextCipheredData;
        }

        public string DecryptString(string cipheredText)
        {
            if (csp == null)
            {
                throw new System.ArgumentException("No keys generated!");
            }

            byte[] byteEncriptedData = Convert.FromBase64String(cipheredText);
            byte[] byteDecriptedData = csp.Decrypt(byteEncriptedData, false);
            string plainTextDecipheredData = System.Text.Encoding.UTF8.GetString(byteDecriptedData);

            return plainTextDecipheredData;
        }

        public RSAParameters ExportPublicKey()
        {
            if (csp != null)
            {
                RSAParameters clePublique = csp.ExportParameters(false);
                return clePublique;
            }
            else
            {
                throw new System.ArgumentException("No keys generated!");
            }
        }

        public RSAParameters ExportPrivateKey()
        {
            if (csp != null)
            {
                RSAParameters clePrive = csp.ExportParameters(true);
                return clePrive;
            }
            else
            {
                throw new System.ArgumentException("No keys generated!");
            }
        }

        public void ImportKey(RSAParameters cle)
        {
            csp.ImportParameters(cle);
        }

        public void ImportBase64PublicKey(string exposant, string modulo)
        {
            RSAParameters clePublique = new RSAParameters();
            clePublique.Modulus = Convert.FromBase64String(modulo);
            clePublique.Exponent = Convert.FromBase64String(exposant);
            csp.ImportParameters(clePublique);
        }

        public void ImportBase64PrivateKey(string exposant, string exposantPrive, string modulo, string p, string q)
        {
            RSAParameters clePrive = csp.ExportParameters(false);
            clePrive.Exponent = Convert.FromBase64String(exposant);
            clePrive.D = Convert.FromBase64String(exposantPrive);
            clePrive.Modulus = Convert.FromBase64String(modulo);
            clePrive.P = Convert.FromBase64String(p);
            clePrive.Q = Convert.FromBase64String(q);


            BigInteger P = new BigInteger(Convert.FromBase64String(p).Concat(new byte[] { 0 }).ToArray());
            BigInteger Q = new BigInteger(Convert.FromBase64String(q).Concat(new byte[] { 0 }).ToArray());
            BigInteger D = new BigInteger(Convert.FromBase64String(exposantPrive).Concat(new byte[] { 0 }).ToArray());
            BigInteger DP = D % (P - 1);
            BigInteger DQ = D % (Q - 1);
            BigInteger InverseQ = ModInverse(Q, P);

            

            byte[] byteDP = DP.ToByteArray();
            byte[] byteDQ = DQ.ToByteArray();
            byte[] byteInverseQ = InverseQ.ToByteArray();



            while (byteDP[byteDP.Length - 1] == 0)//Suppression du byte de signe
            {
                byte[] tmp_byteDP = new byte[byteDP.Length - 1];
                for (int i = 0; i < tmp_byteDP.Length; i++)
                    tmp_byteDP[i] = byteDP[i];

                byteDP = tmp_byteDP;
            }
            
            while (byteDP.Length % 8 != 0 )
            {
                byteDP = new byte[] { 0 }.Concat(byteDP).ToArray();
            }

            while (byteDQ[byteDQ.Length - 1] == 0)//Suppression du byte de signe
            {
                byte[] tmp_byteDQ = new byte[byteDQ.Length - 1];
                for (int i = 0; i < tmp_byteDQ.Length; i++)
                    tmp_byteDQ[i] = byteDQ[i];

                byteDQ = tmp_byteDQ;
            }

            while (byteDQ.Length % 8 != 0)
            {
                byteDQ = new byte[] { 0 }.Concat(byteDQ).ToArray();
            }

            while (byteInverseQ[byteInverseQ.Length - 1] == 0)//Suppression du byte de signe
            {
                byte[] tmp_byteInverseQ = new byte[byteInverseQ.Length - 1];
                for (int i = 0; i < tmp_byteInverseQ.Length; i++)
                    tmp_byteInverseQ[i] = byteInverseQ[i];

                byteInverseQ = tmp_byteInverseQ;
            }

            while (byteInverseQ.Length % 8 != 0)
            {
                byteInverseQ = new byte[] { 0 }.Concat(byteInverseQ).ToArray();
            }


            clePrive.DP = byteDP;
            clePrive.DQ = byteDQ;
            clePrive.InverseQ = byteInverseQ;
            csp.ImportParameters(clePrive);
        }

        public List<string> ExportBase64PublicKey()
        {
            List<string> sortie = new List<string>();

            RSAParameters clePublique = this.ExportPublicKey();
            sortie.Add(Convert.ToBase64String(clePublique.Exponent));
            sortie.Add(Convert.ToBase64String(clePublique.Modulus));

            return sortie;
        }

        public List<string> ExportBase64PrivateKey()
        {
            List<string> sortie = new List<string>();

            RSAParameters clePrive = this.ExportPrivateKey();
            sortie.Add(Convert.ToBase64String(clePrive.Exponent));
            sortie.Add(Convert.ToBase64String(clePrive.D));
            sortie.Add(Convert.ToBase64String(clePrive.Modulus));
            sortie.Add(Convert.ToBase64String(clePrive.P));
            sortie.Add(Convert.ToBase64String(clePrive.Q));



            return sortie;
        }

        public string ExportPublicKeyString()
        {
            List<string> clePublique = this.ExportBase64PublicKey();
            string sortie = "PublicKey{" + clePublique[0] + ";" + clePublique[1] + "}";

            return sortie;
        }

        public string ExportPrivateKeyString()
        {
            List<string> clePrive = this.ExportBase64PrivateKey();
            string sortie = "PrivateKey{" + clePrive[0] + ";" + clePrive[1] + ";" + clePrive[2] + ";" + clePrive[3] + ";" + clePrive[4] + "}";

            return sortie;
        }

        public void ImportPublicKeyString(string cle)
        {
            Regex pattern = new Regex(@"PublicKey\{([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?)\}");

            MatchCollection matches = pattern.Matches(cle);

            if(matches.Count > 0)
            {
                GroupCollection groups = matches[0].Groups;

                string exposant = groups[1].Value;
                string modulo = groups[2].Value;

                this.ImportBase64PublicKey(exposant, modulo);
            }
            else
            {
                throw new System.ArgumentException("Invalid key!");
            }
        }

        public void ImportPrivateKeyString(string cle)
        {
            //PrivateKey{PrivateExponent;Modulus;PrimeP;PrimeQ}
            Regex pattern = new Regex(@"PrivateKey\{([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?)\}");

            MatchCollection matches = pattern.Matches(cle);

            if (matches.Count > 0)
            {
                GroupCollection groups = matches[0].Groups;

                string exposant = groups[1].Value;
                string exposantPrive = groups[2].Value;
                string modulo = groups[3].Value;
                string p = groups[4].Value;
                string q = groups[5].Value;


                this.ImportBase64PrivateKey(exposant, exposantPrive, modulo, p, q);
            }
            else
            {
                throw new System.ArgumentException("Invalid key!");
            }
        }


        

        private static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            //This implementation comes from the pseudocode defining the inverse(a, n) function at
            //https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

            BigInteger t = 0, nt = 1, r = n, nr = a;

            if (n < 0)
            {
                n = -n;
            }

            if (a < 0)
            {
                a = n - (-a % n);
            }

            while (nr != 0)
            {
                var quot = r / nr;

                var tmp = nt; nt = t - quot * nt; t = tmp;
                tmp = nr; nr = r - quot * nr; r = tmp;
            }

            //if (r > 1) throw new ArgumentException(nameof(a) + " is not convertible.");
            if (t < 0) t = t + n;
            return t;
        }

    }

    public class CryptoDeriveBytes
    {
        //This class follows the RFC8018 recommendations for key derivation

        private int hLen = 32;      //length in octets of pseudorandom function output (default HMAC-SHA256)
        private string selectedHMACFunction = "HMACSHA256";

        public CryptoDeriveBytes(string pseudoRandomFunctionName = null)
        {
            if (pseudoRandomFunctionName != null)
                SetPseudoRandomFunction(pseudoRandomFunctionName);
        }

        public void SetPseudoRandomFunction(string functionName)
        {
            if (functionName == "HMACSHA1")
            {
                selectedHMACFunction = "HMACSHA1";
                hLen = 20;
            }
            else if(functionName == "HMACSHA256")
            {
                selectedHMACFunction = "HMACSHA256";
                hLen = 32;
            }
            else if (functionName == "HMACSHA384")
            {
                selectedHMACFunction = "HMACSHA384";
                hLen = 48;
            }
            else if (functionName == "HMACSHA512")
            {
                selectedHMACFunction = "HMACSHA512";
                hLen = 64;
            }
            else
            {
                throw new ArgumentException("bad algorithm name");
            }
        }


        public byte[] DerivesBytes(string password, byte[] salt, int c, int dkLen)
        {
            if (password.Length < 8)
                throw new ArgumentException("password is too short");
            if (salt.Length < 8)
                throw new ArgumentException("salt is too short");
            if (c < 1000)
                throw new ArgumentException("c is too small to be safe");

            byte[] bytePassword = Encoding.UTF8.GetBytes(password);

            int l = (int)Math.Ceiling((double)dkLen / hLen); //length in blocks of derived key, a positive integer
            int r = dkLen - (l - 1) * hLen; //the number of octets in the last block


            IEnumerable<byte> DK = F(bytePassword, salt, c, 0);

            for(int i = 1; i < l; i++)
            {
                DK = DK.Concat(F(bytePassword, salt, c, i));
            }

            byte[] copyOfDK = DK.ToArray();
            byte[] DerivedKEY = new byte[dkLen];
            for(int i = 0; i < dkLen; i++)
            {
                DerivedKEY[i] = copyOfDK[i];
            }

            return DerivedKEY;
        }

        private byte[] F(byte[] password, byte[] salt, int c, int dkIndexBlock)
        {
            byte[] byteI = BitConverter.GetBytes(dkIndexBlock);
            if(BitConverter.IsLittleEndian)
                Array.Reverse(byteI);

            IEnumerable<byte> saltI = salt.Concat(byteI);

            var U = HMAC(password, saltI.ToArray());

            byte[] sortie = U;

            for(int j = 1; j < c; j++)
            {
                sortie = exclusiveOR(sortie, U);
                U = HMAC(password, U);
            }
            sortie = exclusiveOR(sortie, U);

            return U;
        }


        private byte[] HMAC(byte[] key, byte[] message)
        {
            if (selectedHMACFunction == "HMACSHA1")
            {
                return HashHMACSHA1(key, message);
            }
            else if (selectedHMACFunction == "HMACSHA256")
            {
                return HashHMACSHA256(key, message);
            }
            else if (selectedHMACFunction == "HMACSHA384")
            {
                return HashHMACSHA384(key, message);
            }
            else if (selectedHMACFunction == "HMACSHA512")
            {
                return HashHMACSHA512(key, message);
            }
            else
            {
                throw new CryptographicException("Error as occured");
            }
        }

        private byte[] HashHMACSHA1(byte[] key, byte[] message)
        {
            var hash = new HMACSHA1(key);
            return hash.ComputeHash(message);
        }

        private byte[] HashHMACSHA256(byte[] key, byte[] message)
        {
            var hash = new HMACSHA256(key);
            return hash.ComputeHash(message);
        }

        private byte[] HashHMACSHA384(byte[] key, byte[] message)
        {
            var hash = new HMACSHA384(key);
            return hash.ComputeHash(message);
        }

        private byte[] HashHMACSHA512(byte[] key, byte[] message)
        {
            var hash = new HMACSHA512(key);
            return hash.ComputeHash(message);
        }

        private static byte[] exclusiveOR(byte[] arr1, byte[] arr2)
        {
            if (arr1.Length != arr2.Length)
                throw new ArgumentException("arr1 and arr2 are not the same length");

            byte[] result = new byte[arr1.Length];

            for (int i = 0; i < arr1.Length; ++i)
                result[i] = (byte)(arr1[i] ^ arr2[i]);

            return result;
        }
    }
}
