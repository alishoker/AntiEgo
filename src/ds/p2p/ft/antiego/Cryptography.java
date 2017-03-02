package ds.p2p.ft.antiego;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import codec.Base64;
import codec.CorruptedCodeException;


import de.flexiprovider.common.exceptions.InvalidFormatException;
import de.flexiprovider.common.ies.IESParameterSpec;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.ec.FlexiECProvider;
import de.flexiprovider.ec.parameters.CurveParams;
import de.flexiprovider.ec.parameters.CurveRegistry.Secp112r1;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import ds.p2p.ft.antiego.Node.NodeIdentity;
import ds.p2p.ft.antiego.SecureLogging.AccountHashEntry;
import ds.p2p.ft.antiego.Tools.AMSTimer;
import ds.p2p.ft.antiego.Tools.Trace;
/**
 * @author Ali Shoker
 *
 */

public class Cryptography {

	private static final String TAG = "Cryptography";
	static MessageDigest msgDigest;
	static Cipher cipher;
	static IESParameterSpec iESspec;

	static public enum EncryptionType {NONE, ECC, RSA;}
	//static initializer to use for all encryptions 
	static {

		// choose FlexiProvider lib for cryptography
		//if(Node.ENCRYPTION_TYPE==EncryptionType.ECC){
		Security.addProvider(new FlexiCoreProvider());
		Security.addProvider(new FlexiECProvider());

		Trace.d(TAG, "Added providers.");
		//}

		msgDigest = null;
		cipher = null;

		// set cipher and ECC protocols
		try {
			if(Node.ENCRYPTION_TYPE==EncryptionType.ECC)
				cipher = Cipher.getInstance("ECIES", "FlexiEC");
			else if(Node.ENCRYPTION_TYPE==EncryptionType.RSA)
				cipher=Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		iESspec = new IESParameterSpec("AES128_CBC", "HmacSHA1", null, null);

		// set digest protocols
		try {
			msgDigest = MessageDigest.getInstance("MD5", "FlexiCore");

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Trace.d(TAG, "Cryptography module initlaized.");
	}

	// generate keys and fills PublicKey and PrivateKey
	public static void readKeys(NodeIdentity identity,String pub,String prv) {

		// instantiate the elliptic curve key pair generator
		KeyFactory kf=null;
		try {
			if(Node.ENCRYPTION_TYPE==EncryptionType.ECC)
				kf=KeyFactory.getInstance("ECIES", "FlexiEC");
			else if(Node.ENCRYPTION_TYPE==EncryptionType.RSA)
				kf=KeyFactory.getInstance("RSA");
			else if(Node.ENCRYPTION_TYPE==EncryptionType.NONE)
				kf=KeyFactory.getInstance("ECIES", "FlexiEC");//default

		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		X509EncodedKeySpec pubKS = null;
		try {
			pubKS = new X509EncodedKeySpec(
					Base64.decode(pub));
		} catch (CorruptedCodeException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		PKCS8EncodedKeySpec privKS = null;
		try {
			privKS = new PKCS8EncodedKeySpec(
					Base64.decode(prv));
		} catch (CorruptedCodeException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			identity.pubKey=kf.generatePublic(pubKS);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			identity.prvKey=kf.generatePrivate(privKS);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	// generate ECC keys and fills PublicKey and PrivateKey
	public static void generateECCKeys() {

		// instantiate the elliptic curve key pair generator
		KeyPairGenerator kpg = null;
		try {

			kpg = KeyPairGenerator.getInstance("ECIES", "FlexiEC");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// choose the curve, if another one should be used then import it.
		CurveParams ecParams = new Secp112r1();
		//priv:MCwCAQAwEAYHKoZIzj0CAQYFK4EEAAYEFTATAgEBBA4eTydYWGyudeR51SXZ5Q
		//pub:MDIwEAYHKoZIzj0CAQYFK4EEAAYDHgAEtDlatciyDcZXFigozWigcUz2mK5YYM4sWY2bQA



		// Initialize the key pair generator
		try {
			kpg.initialize(ecParams, new SecureRandom());
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		KeyPair keyPair = kpg.generateKeyPair();

		// generate the public key
		Node.publicKey = keyPair.getPublic();
		Trace.d("PubKey: ", Base64.encode(Node.publicKey.getEncoded()));

		// generate private key
		Node.privateKey = keyPair.getPrivate();
		Trace.d("PrivateKey: ", Base64.encode(Node.privateKey.getEncoded()));

	}

	// generate ECC keys and fills PublicKey and PrivateKey
	public static void generateRSAKeys() {

		// instantiate the elliptic curve key pair generator
		KeyPairGenerator kpg = null;
		try {

			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		kpg.initialize(1024);
		KeyPair keyPair = kpg.generateKeyPair();

		// generate the public key
		Node.publicKey = keyPair.getPublic();
		Trace.d("Generated PubKey: ", Base64.encode(Node.publicKey.getEncoded()));

		// generate private key
		Node.privateKey = keyPair.getPrivate();
		Trace.d("Generated PrvKey: ", Base64.encode(Node.privateKey.getEncoded()));
		/*
		 * 
RSA PubKey:MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRs3ySSaBqbZ1AvihCMVrhzVrY
wcOG/NKi9DjqJZ3GbseuLvy9LsY+q1hd+/azqiUQZ5yCWfuYCiWuHZ2Ir1zWJxC1HGBCIj32ls7+
LxfW04N563hMvLmLugOetpcHgEJOjRvo1MwpQil8NXdNsjj+SF8Czt1BaZ9yLET3x0jopwIDAQAB
RSA PrvKey:MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANGzfJJJoGptnUC+K
EIxWuHNWtjB

w4b80qL0OOolncZux64u/L0uxj6rWF379rOqJRBnnIJZ+5gKJa4dnYivXNYnELUcYEIiPfaWzv4v
F9bTg3nreEy8uYu6A562lweAQk6NG+jUzClCKXw1d02yOP5IXwLO3UFpn3IsRPfHSOinAgMBAAEC
gYAt9taeRg8oZOBsGYI/iAvwpI9+JXKTOwV8fGWhRR+BKDUSg/AYE5GWmP4kk57uoKPBJcTTeZ/B
IrBBqvIlzLJfRL3freISsJ87wZiLMJKy1Ej32anjRcKFZ1OMd97AGnoROtOQihbjj5HApgpFs7dp
KYonhpY4QnzIIEoXedrN8QJBAPMr8PkJga62k0akOCHeB7iVUtyg/TFIzqgIdWfVAqnvAlZQB4Uz
qCGmhiABqt0MhoGbKMrGIcnxVdXikFNszekCQQDcw4W3D/THifKLWHiCj9eSDNH8lEBHPiQ9QGZk
EWmO14kTMYr94N1A/mwCe0EaHxquDzKyxveMoO4Sls1j4xgPAkEAuj0QLJukT7wTJcpGF2ImRa9P
rBw8bk+VvsnjqWdRx/Z+sr5OVC0Q+ty/4qmERBIAviioYEzIuhJ0q//+i3ZMaQJACmfI2K0O24zb
+sdrvrOq9H5YM3CFaxY5vQ1ZBiRv9kSgeGAgbgD4TMTxMFjA48tNhaC/wf9w0ZcQQZ4MBkZA7wJA
NZEmuwkT8Ovsjxah0rbYZJw+cgM9tFqb+eWeU5dU+rRObMgh/rpaYiHadYeu7VnxeWsLK4wHzXip
IZsZShxj3Q
		 */

	}

	// digest method String to String
	public static String digestMessage(String message) {

		String digest = null;

		try {
			digest = new String(msgDigest.digest(message.getBytes("UTF-8")),
					"UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		return digest;
	}

	// digest method byte[] to byte[]
	public static byte[] digestMessage(byte[] bytes) {

		return msgDigest.digest(bytes);
	}

	//get digest of an old hash + an entry
	public static String digestEntry(String oldhash, Long seqId){

		if(oldhash==null)
			oldhash="";
			return digestMessage(oldhash + String.valueOf(seqId));
	}

	public static String digestHashMap(Map<Long, AccountHashEntry> hashMap){
		String tmp=null;
		AMSTimer timer=new AMSTimer();
		timer.start();
		Long sum=Long.valueOf(0);

		//Note: we are using the keys since using values() gives terrible performance.
		for (Iterator<Long> iterator = hashMap.keySet().iterator(); iterator.hasNext();) {
			sum+=iterator.next();

		}
		tmp=String.valueOf(sum);

		Trace.d(TAG, "Iterate to sum msg time:"+ timer.stop());

		timer.start();
		String msg= Cryptography.digestMessage(tmp);
		Trace.d(TAG, "digestMessage time:"+ timer.stop());
		return msg;
	}

	public static String encryptMessage(PublicKey publicKey, String message) {

		byte[] byteMessage = null;
		byte[] encryptedData = null;
		String encryptedMessage = null;

		try {
			byteMessage = Base64.decode(message.getBytes("UTF-8"));
			//Trace.d(TAG, "Message size before encryption:"+byteMessage.length);
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (CorruptedCodeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// set cipher mode to encrypt
		try {
			if(Node.ENCRYPTION_TYPE==EncryptionType.ECC)
				cipher.init(Cipher.ENCRYPT_MODE, publicKey, iESspec);
			else if(Node.ENCRYPTION_TYPE==EncryptionType.RSA)
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidAlgorithmParameterException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// encrypt the message
		try {
			AMSTimer timer= new AMSTimer();
			timer.start();
			encryptedData = cipher.doFinal(byteMessage);
			//Trace.d("Encryption time",timer.end().toString());

			// Trace.d("Encryption time:", Long.toString(duration));

		} catch (IllegalBlockSizeException e) {
			Trace.e(TAG, e.toString());
		} catch (BadPaddingException e) {
			Trace.e(TAG, e.toString());
		}

		try {
			encryptedMessage = new String(Base64.encode(encryptedData).
					getBytes("UTF-8"), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//Trace.d("encryptedMessage", encryptedMessage);

		return encryptedMessage;
	}

	// encrypt array of bytes in Base64 to an array of bytes in Base64
	public static byte[] encryptMessage(PublicKey publicKey, byte[] message) {

		byte[] encryptedData = null;

		// set cipher mode to encrypt
		try {
			if(Node.ENCRYPTION_TYPE==EncryptionType.ECC)
				cipher.init(Cipher.ENCRYPT_MODE, publicKey, iESspec);
			else if(Node.ENCRYPTION_TYPE==EncryptionType.RSA)
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidAlgorithmParameterException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// encrypt the message
		try {
			// long startTime = System.currentTimeMillis();
			encryptedData = cipher.doFinal(message);

			// long endTime = System.currentTimeMillis();
			// long duration = endTime - startTime;
			// Trace.d("Encryption time:", Long.toString(duration));

		} catch (IllegalBlockSizeException e) {
			Trace.e(TAG, e.toString());
		} catch (BadPaddingException e) {
			Trace.e(TAG, e.toString());
		}

		return encryptedData;
	}

	// decrypt function string to string
	public static String decryptMessage(PrivateKey privateKey, String message) {

		// decrypt the message
		byte[] decryptedData = null;
		byte[] encryptedMessage = null;
		String decryptedMessage = null;

		try {
			encryptedMessage = Base64.decode(message.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (CorruptedCodeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Trace.d("decryptMessage: ENCRYPTED_MESSAGE ", message);

		try {
			if(Node.ENCRYPTION_TYPE==EncryptionType.ECC)
				cipher.init(Cipher.DECRYPT_MODE, privateKey, iESspec);
			else if(Node.ENCRYPTION_TYPE==EncryptionType.RSA)
				cipher.init(Cipher.DECRYPT_MODE, privateKey);

		} catch (Exception e) {
			Trace.e(TAG, e.toString());
		}

		try {
			// long startTime = System.currentTimeMillis();
			decryptedData = cipher.doFinal(encryptedMessage);

			// long endTime = System.currentTimeMillis();
			// long duration = endTime - startTime;
			// Trace.d("Decryption time:", Long.toString(duration));

		} catch (IllegalBlockSizeException e) {
			Trace.e(TAG, e.toString());
			e.printStackTrace();
		} catch (BadPaddingException e) {
			Trace.e(TAG, e.toString());
			e.printStackTrace();
		} catch (InvalidFormatException e) {
			// TODO: handle exception
			Trace.e(TAG, e.toString());
			e.printStackTrace();
		}

		try {
			decryptedMessage = new String(Base64.encode(decryptedData).
					getBytes("UTF-8"), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Trace.d("decryptedMessage: ", decryptedMessage);

		return decryptedMessage;
	}

	// decrypt function byte[] Base64 to byte[] Base64
	public static byte[] decryptMessage(PrivateKey privateKey, byte[] message) {

		byte[] decryptedData = null;

		try {
			if(Node.ENCRYPTION_TYPE==EncryptionType.ECC)
				cipher.init(Cipher.DECRYPT_MODE, privateKey, iESspec);
			else 	if(Node.ENCRYPTION_TYPE==EncryptionType.RSA)
				cipher.init(Cipher.DECRYPT_MODE, privateKey);

		} catch (Exception e) {
			Trace.e(TAG, e.toString());
		}

		try {
			// long startTime = System.currentTimeMillis();
			decryptedData = cipher.doFinal(message);

			// long endTime = System.currentTimeMillis();
			// long duration = endTime - startTime;
			// Trace.d("Decryption time:", Long.toString(duration));

		} catch (IllegalBlockSizeException e) {
			Trace.e(TAG, e.toString());
		} catch (BadPaddingException e) {
			Trace.e(TAG, e.toString());
		}

		// Trace.d("decryptedMessage: ", decryptedMessage);

		return decryptedData;
	}

}
