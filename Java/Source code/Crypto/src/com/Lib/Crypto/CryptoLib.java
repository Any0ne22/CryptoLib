/*
CryptoLib v1.1
Made by Tom Gouville
https://github.com/Any0ne22/CryptoLib/
*/
package com.Lib.Crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.*;


public class CryptoLib {

    static public class CryptoAES
    {
        private byte[] key = new byte[32];
        private byte[] iv = new byte[16];
        private String mode = "CBC";

        public CryptoAES(String password) throws Throwable
        {
            if(password!=null)
                GenerateAlgotihmInputs(password);
        }

        public CryptoAES() {
			
		}
        
        public void setCipherMode(String cipherMode) throws Throwable
        {
        	if(cipherMode == "CBC")
        	{
        		mode = "CBC";
        	}
        	else if(cipherMode == "ECB")
        	{
        		mode = "ECB";
        	}
        	else
        	{
        		throw new Throwable("Bad cipher mode!");
        	}
        }

        public List<byte[]> GenerateAlgotihmInputs(String password) throws Throwable
        {
            return GenerateAlgotihmInputs(password, "HMACSHA256" , 10000);
        }
        
		public List<byte[]> GenerateAlgotihmInputs(String password, String hmacAlgorithm , int derivationIterationsCount) throws Throwable
        {
            List<byte[]> result = new ArrayList<byte[]>();

            try {
            	CryptoDeriveBytes derivation = new CryptoDeriveBytes();
                derivation.SetPseudoRandomFunction(hmacAlgorithm);
                byte[] derivedKey = derivation.DerivesBytes(password, password.getBytes("UTF-8"), derivationIterationsCount, 64);
                
                System.arraycopy(derivedKey, 0, key, 0, 32);
                System.arraycopy(derivedKey, 32, iv, 0, 16);

                result.add(key);
                result.add(iv);
            }
            catch (Exception e) {
            	
            }

            return result;
        }

        public String EncryptString(String clearText, byte[] encryptKey, byte[] encryptIv) {

            String sortie = "";
            try {
                SecretKeySpec secret = new SecretKeySpec(encryptKey, "AES");
                AlgorithmParameterSpec ivSpec = new IvParameterSpec(encryptIv);
                Cipher cipher = Cipher.getInstance("AES/"+ mode +"/PKCS5Padding");
                if(mode == "CBC")
                {
                	cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
                }
                else
                {
                	cipher.init(Cipher.ENCRYPT_MODE, secret);
                }
                byte[] result = cipher.doFinal(clearText.getBytes("UTF-8"));

                sortie = Base64.getEncoder().encodeToString(result);
            }
            catch(Exception e) {
            	System.out.println(e);
            }

            return sortie;
        }

        public String EncryptString(String clearText) {
            return EncryptString(clearText, key, iv);
        }

        public String DecryptString(String cipherText, byte[] encryptKey, byte[] encryptIv) throws IOException {

            String sortie = "";
            byte[] cipherTextUTF8 = Base64.getDecoder().decode(cipherText);

            try {
                SecretKeySpec secret = new SecretKeySpec(encryptKey, "AES");
                AlgorithmParameterSpec ivSpec = new IvParameterSpec(encryptIv);
                Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
                if(mode == "CBC")
                {
                	cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
                }
                else
                {
                	cipher.init(Cipher.DECRYPT_MODE, secret);
                }
                byte[] result = cipher.doFinal(cipherTextUTF8);

                sortie = new String(result, StandardCharsets.UTF_8);
            }
            catch(Exception e) {

            }

            return sortie;
        }

        public String DecryptString(String cipherText) throws IOException {
            return DecryptString(cipherText, key, iv);
        }
    }

    static public class CryptoRSA
    {
        private PublicKey publicKey = null;
        private PrivateKey privateKey = null;


        public CryptoRSA(int keysize) throws NoSuchAlgorithmException {
            GenerateKeys(keysize);
        }

        public CryptoRSA(){

        }

        public void GenerateKeys(int keySize) throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            KeyPair keys = generator.genKeyPair();
            publicKey = keys.getPublic();
            privateKey = keys.getPrivate();
        }
        public void GenerateKeys() throws NoSuchAlgorithmException      //Default keysize
        {
            GenerateKeys(2048);
        }

        public String EncryptString(String clearText) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            byte[] text = clearText.getBytes("UTF-8");

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(text);

            String sortie = Base64.getEncoder().encodeToString(encryptedBytes);

            return sortie;
        }

        public String DecryptString(String cipheredText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
            byte[] cipherTextUTF8 = Base64.getDecoder().decode(cipheredText);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(cipherTextUTF8);
            String sortie = new String(decryptedBytes, StandardCharsets.UTF_8);

            return sortie;
        }



        public PublicKey ExportPublicKey() throws Throwable {
            if(publicKey != null)
            {
                return publicKey;
            }
            else
            {
                throw new Throwable("No keys generated!");
            }
        }

        public PrivateKey ExportPrivateKey() throws Throwable {
            if(privateKey != null)
            {
                return privateKey;
            }
            else
            {
                throw new Throwable("No keys generated!");
            }
        }

        public void ImportKey(PublicKey key) throws Throwable {
            if(key != null)
            {
                publicKey = key;
            }
            else
            {
                throw new Throwable("Key can't be null!");
            }
        }
        public void ImportKey(PrivateKey key) throws Throwable {
            if(key != null)
            {
                privateKey = key;
            }
            else
            {
                throw new Throwable("Key can't be null!");
            }
        }

        public void ImportBase64PublicKey(String exposant, String modulo) throws Throwable {
            PublicKey cle;
            BigInteger modulus = new BigInteger(1, Base64.getDecoder().decode(modulo));
            BigInteger exponent = new BigInteger(1,Base64.getDecoder().decode(exposant));

            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            cle = factory.generatePublic(spec);
            ImportKey(cle);
        }
        
        public void ImportBase64PrivateKey(String exposant, String exposantPrive, String modulo, String p, String q) throws Throwable {
            PrivateKey cle;
            BigInteger modulus = new BigInteger(1, Base64.getDecoder().decode(modulo));
            BigInteger exponent = new BigInteger(1,Base64.getDecoder().decode(exposant));
            BigInteger privateExponent= new BigInteger(1,Base64.getDecoder().decode(exposantPrive));
            BigInteger P = new BigInteger(1,Base64.getDecoder().decode(p));
            BigInteger Q = new BigInteger(1,Base64.getDecoder().decode(q));
            
            BigInteger un = BigInteger.ONE;
            
            
            BigInteger primeExponentP = privateExponent.mod(P.subtract(un));
            BigInteger primeExponentQ = privateExponent.mod(Q.subtract(un));
            BigInteger crtCoefficient = Q.modInverse(P);
            		
            

            RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(modulus, exponent, privateExponent, P, Q, primeExponentP, primeExponentQ, crtCoefficient);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            cle = factory.generatePrivate(spec);
            ImportKey(cle);
        }
        
        public List<String> ExportBase64PublicKey() throws Throwable
        {
        	List<String> sortie= new ArrayList<String>();

        	
            PublicKey clePublique = this.ExportPublicKey();
            
            RSAPublicKey clePublicRSA = (RSAPublicKey)clePublique;
            
            BigInteger exposant = clePublicRSA.getPublicExponent();
            BigInteger modulo = clePublicRSA.getModulus();
            
            byte[] byteExposant = exposant.toByteArray();
            if (byteExposant[0] == 0) {						//Suppression de l'octet de signe
                byte[] tmp = new byte[byteExposant.length - 1];
                System.arraycopy(byteExposant, 1, tmp, 0, tmp.length);
                byteExposant = tmp;
            }
            
            byte[] byteModulo = modulo.toByteArray();
            if (byteModulo[0] == 0) {						//Suppression de l'octet de signe
                byte[] tmp = new byte[byteModulo.length - 1];
                System.arraycopy(byteModulo, 1, tmp, 0, tmp.length);
                byteModulo = tmp;
            }
            
            
            sortie.add(Base64.getEncoder().encodeToString(byteExposant));
            sortie.add(Base64.getEncoder().encodeToString(byteModulo));

            return sortie;
        }
        
        public List<String> ExportBase64PrivateKey() throws Throwable
        {
        	List<String> sortie= new ArrayList<String>();

        	
            PrivateKey clePrive = this.ExportPrivateKey();
            
            RSAPrivateCrtKey clePriveRSA = (RSAPrivateCrtKey)clePrive;
            
            
            BigInteger exposant = clePriveRSA.getPublicExponent();
            BigInteger exposantPrive = clePriveRSA.getPrivateExponent();
            BigInteger modulo = clePriveRSA.getModulus();
            BigInteger P = clePriveRSA.getPrimeP();
            BigInteger Q = clePriveRSA.getPrimeQ();
            
            
            
            byte[] byteExposant = exposant.toByteArray();
            if (byteExposant[0] == 0) {						//Suppression de l'octet de signe
                byte[] tmp = new byte[byteExposant.length - 1];
                System.arraycopy(byteExposant, 1, tmp, 0, tmp.length);
                byteExposant = tmp;
            }
            
            byte[] byteExposantPrive = exposantPrive.toByteArray();
            if (byteExposantPrive[0] == 0) {						//Suppression de l'octet de signe
                byte[] tmp = new byte[byteExposantPrive.length - 1];
                System.arraycopy(byteExposantPrive, 1, tmp, 0, tmp.length);
                byteExposantPrive = tmp;
            }
            
            byte[] byteModulo = modulo.toByteArray();
            if (byteModulo[0] == 0) {						//Suppression de l'octet de signe
                byte[] tmp = new byte[byteModulo.length - 1];
                System.arraycopy(byteModulo, 1, tmp, 0, tmp.length);
                byteModulo = tmp;
            }
            
            byte[] byteP = P.toByteArray();
            if (byteP[0] == 0) {						//Suppression de l'octet de signe
                byte[] tmp = new byte[byteP.length - 1];
                System.arraycopy(byteP, 1, tmp, 0, tmp.length);
                byteP = tmp;
            }
            
            byte[] byteQ = Q.toByteArray();
            if (byteQ[0] == 0) {						//Suppression de l'octet de signe
                byte[] tmp = new byte[byteQ.length - 1];
                System.arraycopy(byteQ, 1, tmp, 0, tmp.length);
                byteQ = tmp;
            }
            
            
            sortie.add(Base64.getEncoder().encodeToString(byteExposant));
            sortie.add(Base64.getEncoder().encodeToString(byteExposantPrive));
            sortie.add(Base64.getEncoder().encodeToString(byteModulo));
            sortie.add(Base64.getEncoder().encodeToString(byteP));
            sortie.add(Base64.getEncoder().encodeToString(byteQ));
            

            return sortie;
        }
        
        public String ExportPublicKeyString() throws Throwable
        {
        	List<String> clePublique = this.ExportBase64PublicKey();
            String sortie = "PublicKey{" + clePublique.get(0) + ";" + clePublique.get(1) + "}";

            return sortie;
        }
        
        public String ExportPrivateKeyString() throws Throwable
        {
        	List<String> clePrive = this.ExportBase64PrivateKey();
            String sortie = "PrivateKey{" + clePrive.get(0) + ";" + clePrive.get(1) + ";" + clePrive.get(2) + ";" + clePrive.get(3) + ";" + clePrive.get(4) +"}";

            return sortie;
        }

        public void ImportPublicKeyString(String cle) throws Throwable
        {
        	Pattern p = Pattern.compile("PublicKey\\{([a-zA-Z0-9\\+\\/\\=]+?);([a-zA-Z0-9\\+\\/\\=]+?)\\}");
        	Matcher m = p.matcher(cle);
        	boolean b = m.matches();
        	if(b) {
        	    this.ImportBase64PublicKey(m.group(1), m.group(2));
        	}
        	else
        	{
        		throw new Throwable("Invalid key!");
        	}
        }
        
        public void ImportPrivateKeyString(String cle) throws Throwable
        {
        	Pattern p = Pattern.compile("PrivateKey\\{([a-zA-Z0-9\\+\\/\\=]+?);([a-zA-Z0-9\\+\\/\\=]+?);([a-zA-Z0-9\\+\\/\\=]+?);([a-zA-Z0-9\\+\\/\\=]+?);([a-zA-Z0-9\\+\\/\\=]+?)\\}");
        	Matcher m = p.matcher(cle);
        	boolean b = m.matches();
        	if(b) {
        	    this.ImportBase64PrivateKey(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5));
        	}
        	else
        	{
        		throw new Throwable("Invalid key!");
        	}
        }
    }
    
    static public class CryptoDeriveBytes
    {
        //This class follows the RFC8018 recommendations for key derivation

        private int hLen = 32;      //length in octets of pseudorandom function output (default HMAC-SHA256)
        private String selectedHMACFunction = "HMACSHA256";

        
        public CryptoDeriveBytes()
        {
            
        }
        
        public CryptoDeriveBytes(String pseudoRandomFunctionName) throws Throwable
        {
            SetPseudoRandomFunction(pseudoRandomFunctionName);
        }

        public void SetPseudoRandomFunction(String functionName) throws Throwable
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
            	throw new Throwable("bad algorithm name");
            }
        }


        public byte[] DerivesBytes(String password, byte[] salt, int c, int dkLen) throws IOException, Throwable
        {
            if (password.length() < 8)
            	throw new Throwable("password is too short");
            if (salt.length < 8)
            	throw new Throwable("salt is too short");
            if (c < 1000)
            	throw new Throwable("c is too small to be safe");

            byte[] bytePassword = password.getBytes("UTF-8");

            int l = (int)Math.ceil((double)dkLen / hLen); //length in blocks of derived key, a positive integer
            int r = dkLen - (l - 1) * hLen; //the number of octets in the last block


            ByteArrayOutputStream DK = new ByteArrayOutputStream( );
            DK.write(F(bytePassword, salt, c, 0));

            for(int i = 1; i < l; i++)
            {
            	DK.write(F(bytePassword, salt, c, i));
            }

            byte[] copyOfDK = DK.toByteArray();
            byte[] DerivedKEY = new byte[dkLen];
            for(int i = 0; i < dkLen; i++)
            {
                DerivedKEY[i] = copyOfDK[i];
            }

            return DerivedKEY;
        }

        private byte[] F(byte[] password, byte[] salt, int c, int dkIndexBlock) throws Throwable
        {
            byte[] byteI = ByteBuffer.allocate(4).putInt(dkIndexBlock).array();

            
            ByteArrayOutputStream saltI = new ByteArrayOutputStream( );
            saltI.write( salt );
            saltI.write( byteI );


            byte[] U = HMAC(password, saltI.toByteArray());

            byte[] sortie = U;

            for(int j = 1; j < c; j++)
            {
                sortie = exclusiveOR(sortie, U);
                U = HMAC(password, U);
            }
            sortie = exclusiveOR(sortie, U);

            return U;
        }


        private byte[] HMAC(byte[] key, byte[] message) throws Throwable
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
            	throw new Throwable("Error as occured");
            }
        }

        public byte[] HashHMACSHA1(byte[] key, byte[] message) throws InvalidKeyException, NoSuchAlgorithmException
        {
        	  Mac sha256_HMAC = Mac.getInstance("HmacSHA1");
        	  SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA1");
        	  sha256_HMAC.init(secret_key);

        	  return sha256_HMAC.doFinal(message);
        }

        public byte[] HashHMACSHA256(byte[] key, byte[] message) throws InvalidKeyException, NoSuchAlgorithmException
        {
        	  Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        	  SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        	  sha256_HMAC.init(secret_key);

        	  return sha256_HMAC.doFinal(message);
        }

        public byte[] HashHMACSHA384(byte[] key, byte[] message) throws InvalidKeyException, NoSuchAlgorithmException
        {
        	  Mac sha256_HMAC = Mac.getInstance("HmacSHA384");
        	  SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA384");
        	  sha256_HMAC.init(secret_key);

        	  return sha256_HMAC.doFinal(message);
        }

        public byte[] HashHMACSHA512(byte[] key, byte[] message) throws InvalidKeyException, NoSuchAlgorithmException
        {
        	  Mac sha256_HMAC = Mac.getInstance("HmacSHA512");
        	  SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA512");
        	  sha256_HMAC.init(secret_key);

        	  return sha256_HMAC.doFinal(message);
        }

        private byte[] exclusiveOR(byte[] arr1, byte[] arr2) throws Throwable
        {
            if (arr1.length != arr2.length)
                throw new Throwable("arr1 and arr2 are not the same length");

            byte[] result = new byte[arr1.length];

            for (int i = 0; i < arr1.length; ++i)
                result[i] = (byte)(arr1[i] ^ arr2[i]);

            return result;
        }
    }
}
