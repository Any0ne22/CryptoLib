

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.Lib.Crypto.CryptoLib;
import com.Lib.Crypto.CryptoLib.CryptoAES;
import com.Lib.Crypto.CryptoLib.CryptoRSA;

public class Main {

	public static void main(String[] args) 
	{
		
		
		CryptoLib.CryptoRSA Crypto = null;
		
		try {
			Crypto = new CryptoRSA(2048);
		} catch (NoSuchAlgorithmException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		
		try {
			System.out.println(Crypto.ExportPrivateKeyString());

		} catch (Throwable e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		String chiffre;

		Scanner scanInput = new Scanner(System.in);
		chiffre = scanInput.nextLine();

		scanInput.close();

		
		try {
			System.out.println(Crypto.EncryptString("test8000"));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
	}

}
