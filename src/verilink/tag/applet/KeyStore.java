package verilink.tag.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javacard.framework.CardRuntimeException;
import javacard.security.CryptoException;

/**
 * Storage for private key
 * 
 * @author isaacdubuque
 */
public class KeyStore {
	/**
	 * Encryption for encrypting private keys
	 */
	private static final byte ENCRYPTION_KEY_TYPE = KeyBuilder.TYPE_AES;
	
	/**
	 * AES encryption used for encrypting private key
	 */
	private static final byte ENCRYPTION_MODE = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
	
	/**
	 * Length of the AES key.
	 */
	private static final short ENCRYPTION_KEY_LENGTH = KeyBuilder.LENGTH_AES_128;
	
	/**
	 * Max length of private key in bytes
	 */
	private static final short PRIVATE_KEY_SIZE = 32;
	
	/**
	 * Max length of public key in bytes
	 */
	private static final short PUBLIC_KEY_SIZE = 65;
	
	/**
	 * Invalid Key Handle
	 */
	private static final short INVALID_KEY_HANDLE = 0xFF;
	
	/**
	 * Max Store Size
	 */
	private static final short MAX_KEY_STORE_SIZE = 0xFF;
	
	/**
	 * EC Private Key, Public Key container
	 */
	private ECKeyPair[] ecKeys;
	
	/**
	 * Current number of registered keys
	 */
	private short numberOfKeys;
	
	/**
	 * Max number of keys declared
	 */
	private short MAX_KEYS;
	
	/**
	 * Key used for encryption of the private keys.
	 */
	private AESKey aesKey;
	
	/**
	 * Cipher used for AES encryption of private keys.
	 */
	private Cipher aesCipher;
	
	/**
	 * Used to generate the keys and sign transactions
	 */
	private KeyPair keyPair;
	
	/**
	 * Signature used to sign messages
	 */
	private Signature signature;
	
	/**
	 * Buffer used to encrypt keys and store temporary data
	 */
	private byte[] keyBuffer;
	
	/**
	 * Buffer used for encryption
	 */
	private byte[] encryptionBuffer;
	
	/**
	 * Constructor. Has to be called inside the constructor of the applet to
	 * reserve needed memory.
	 * 
	 * @param storeSize the size of the keystore in keys. Max 254.
	 */
	public KeyStore(short storeSize)
	{
		if(storeSize >= MAX_KEY_STORE_SIZE)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		MAX_KEYS = storeSize;
		
		keyBuffer = new byte[256];
		encryptionBuffer = new byte[64];
		
		RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(
				keyBuffer, (short) 0, (short) (ENCRYPTION_KEY_LENGTH / 8));
		
		aesKey = (AESKey) KeyBuilder.buildKey(ENCRYPTION_KEY_TYPE, 
				ENCRYPTION_KEY_LENGTH, false);
		aesKey.setKey(keyBuffer, (short) 0);
		
		aesCipher = Cipher.getInstance(ENCRYPTION_MODE, false);
		
		keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		
		// Set SECP256K1
		ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

		privKey.setFieldFP(SECP256K1.P, (short) 0, (short) SECP256K1.P.length);
		privKey.setA(SECP256K1.a, (short) 0, (short) SECP256K1.a.length);
		privKey.setB(SECP256K1.b, (short) 0, (short) SECP256K1.b.length);
		privKey.setG(SECP256K1.G, (short) 0, (short) SECP256K1.G.length);
		privKey.setR(SECP256K1.R, (short) 0, (short) SECP256K1.R.length);
		privKey.setK(SECP256K1.K);

		ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

		pubKey.setFieldFP(SECP256K1.P, (short) 0, (short) SECP256K1.P.length);
		pubKey.setA(SECP256K1.a, (short) 0, (short) SECP256K1.a.length);
		pubKey.setB(SECP256K1.b, (short) 0, (short) SECP256K1.b.length);
		pubKey.setG(SECP256K1.G, (short) 0, (short) SECP256K1.G.length);
		pubKey.setR(SECP256K1.R, (short) 0, (short) SECP256K1.R.length);
		pubKey.setK(SECP256K1.K);
		
		ecKeys = new ECKeyPair[storeSize];
		
		/* allocate memory for keys */
		for (short i = 0; i < ecKeys.length; i++)
		{
			ecKeys[i] = new ECKeyPair(PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE);
		}
	}
	
	/**
	 * Check if key handle is valid
	 * @param keyHandle
	 * @return true valid or false invalid
	 */
	public boolean isValidKeyHandle(short keyHandle)
	{
		if((keyHandle == INVALID_KEY_HANDLE) || 
			(keyHandle >= MAX_KEYS)) 
		{
			return false;
		}
		
		return ecKeys[keyHandle].isValid();
	}
	
	/**
	 * Signs the given sha256Hash with the currently selected key
	 * 
	 * @param src The buffer containing the sha256hash
	 * @param msgOff the offset of the msg in sha256hash
	 * @param msgLength the length of the sha256 message
	 * @param dest the destination of the signed message
	 * @param destOff the offset for the dest buffer
	 * 
	 * @return length of the signed message
	 */
	public short signMessage(short keyHandle, byte[] src, short msgOff, short msgLength,
		byte[] dest, short destOff)
	{
		if(!isValidKeyHandle(keyHandle))
		{
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}
		
		/* de-crypt private key and place in key buffer */
		short keyLength = decryptPrivateKey(ecKeys[keyHandle], keyBuffer, (short) 0);
		
		/* Set private key from key buffer */
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		privateKey.setS(keyBuffer,  (short) 0, keyLength);
		
		/* init ECDSA with private key */
		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		signature.init(privateKey, Signature.MODE_SIGN);
		
		/* Sign message and return length */
		return signature.sign(src,  msgOff, msgLength, dest, destOff);	
	}
	
	/**
	 * Gets the public key of the currently selected handle
	 * 
	 * @param destination for pubkey to be copied
	 * @param dest offset of buffer
	 * 
	 * @return length of the public key
	 */
	public short getPublicKey(short keyHandle, byte[] dest, short destOff)
	{
		if(!isValidKeyHandle(keyHandle))
		{
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}
		
		return ecKeys[keyHandle].getPublicKey(dest, destOff);
	}
	
	/**
	 * Generates new ECDSA key pair and returns the public key handle if storage is available
	 * 
	 * @return the key handle
	 */
	public short generateKeyPair()
	{
		short keyHandle, privateKeyLength, pubKeyLength;
		
		/* get the first open key handle */
		keyHandle = findFirstFreeKeyHandle();
		
		if(keyHandle == INVALID_KEY_HANDLE)
		{
			ISOException.throwIt(StatusCodes.KEY_GEN_FAILED);
		}
		
		/* Generate the public and private keys */
		keyPair.genKeyPair();
		
		ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
		
		/* Encrypt the private key */
		privateKeyLength = encryptPrivateKey(
				(ECPrivateKey) keyPair.getPrivate(), keyBuffer, (short) 0);
		
		/* add public key to buffer */
		pubKeyLength = pubKey.getW(keyBuffer, privateKeyLength);
		
		/* store the public and private keys */
		ecKeys[keyHandle].setKey(
			keyBuffer, (short) 0, privateKeyLength,
			keyBuffer, privateKeyLength, pubKeyLength
		);
		
		return keyHandle;
	}
	
	
	/**
	 * Encrypts the private key for AES for storage
	 * 
	 * @param privateKey the private key to encrypt
	 * @param dest the destination to put the key
	 * @destOff the offset inside the destination array
	 * 
	 * @return the length of the encrypted key
	 */
	public short encryptPrivateKey(ECPrivateKey privateKey, byte[] dest,
			short destOff)
	{
		short keyLength = privateKey.getS(encryptionBuffer, (short) 0);
		
		if(keyLength != PRIVATE_KEY_SIZE)
		{
			ISOException.throwIt(StatusCodes.WRONG_PRIVATE_KEY_LENGTH);
		}
		
		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
		
		
		return aesCipher.doFinal(encryptionBuffer, (short) 0, PRIVATE_KEY_SIZE, 
				dest, destOff);
	}
	
	/**
	 * Decrypts the private key with the AES key for this store
	 * 
	 * @param privateKey the private key to decrypt
	 * @param dest the destination to place the decrypted key
	 * @param destOff the offset inside the destination array
	 * 
	 * @return length of the decrypted key
	 */
	private short decryptPrivateKey(ECKeyPair keyPair,
			byte[] dest, short destOff)
	{
		short keyLength = keyPair.getPrivateKey(encryptionBuffer,  (short) 0);
		
		if(keyLength != PRIVATE_KEY_SIZE)
		{
			ISOException.throwIt(StatusCodes.WRONG_PRIVATE_KEY_LENGTH);
		}
		
		aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
		aesCipher.doFinal(encryptionBuffer, (short) 0, keyLength, encryptionBuffer, (short) 0);
		
		Util.arrayCopy(encryptionBuffer, (short) 0, dest, destOff, PRIVATE_KEY_SIZE);
		
		return keyLength;
	}
	
	/**
	 * Deletes the given private key handle
	 * 
	 * @param the handle for the key
	 */
	public void deletePrivateKey(short keyHandle)
	{
		if(!isValidKeyHandle(keyHandle))
		{
			ISOException.throwIt(StatusCodes.KEY_GET_FAILED);
		}
		else
		{
			ecKeys[keyHandle].clear();
		}
	}
	
	/**
	 * Get number of keys
	 * 
	 * @return the number of registered keys
	 */
	public short getNumberOfKeys()
	{
		numberOfKeys = (short) 0;
		
		for(short i = 0; i < (short) ecKeys.length; i++)
		{
			if(ecKeys[i].isValid())
			{
				numberOfKeys = (short) (numberOfKeys + 1);
			}
		}
		
		return numberOfKeys;
	}
	
	/**
	 * Calculates number of free keys
	 * 
	 * @return number of free spaces for keys
	 */
	public short getNumberOfKeysRemaining()
	{
		return (short) (MAX_KEYS - getNumberOfKeys());
	}
	
	/**
	 * Determine whether the key store is full
	 */
	public boolean isFull()
	{
		return getNumberOfKeys() == MAX_KEYS;
	}
	
	/**
	 * Find first free position to add a key
	 * 
	 * @return next free key handle
	 */
	public short findFirstFreeKeyHandle()
	{
		short freeKeyHandle = (short) 0;
		
		while(freeKeyHandle < MAX_KEYS)
		{
			if(!ecKeys[freeKeyHandle].isValid())
			{
				return freeKeyHandle;
			}
			
			freeKeyHandle++;
		}
		
		return INVALID_KEY_HANDLE;
	}	
}