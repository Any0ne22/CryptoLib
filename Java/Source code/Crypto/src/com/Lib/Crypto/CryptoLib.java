/*
CryptoLib v1.0
Made by Tom Gouville
https://github.com/Any0ne22/CryptoLib/
*/
package com.Lib.Crypto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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


        public CryptoAES(String password)
        {
            if(password!=null)
                GenerateAlgotihmInputs(password);
        }

        public CryptoAES() {
			
		}

		public List<byte[]> GenerateAlgotihmInputs(String password)
        {
            List<byte[]> result = new ArrayList<byte[]>();

            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), password.getBytes("UTF-8"), 1000, 384);
                Key secretKey = factory.generateSecret(pbeKeySpec);
                System.arraycopy(secretKey.getEncoded(), 0, key, 0, 32);
                System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);

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
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
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
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
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
}
