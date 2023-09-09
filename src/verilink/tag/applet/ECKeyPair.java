package verilink.tag.applet;

import javacard.framework.CardRuntimeException;
import javacard.framework.Util;


/**
 * Container for public and private key pair
 * 
 * @author isaacdubuque
 *
 */
public class ECKeyPair {
	
	/**
	 * Private Key AES encrypted
	 */
	byte[] ePrivateKey;
	
	/**
	 * public key
	 */
	byte[] pubKey;
	
	/**
	 * Is key generated
	 */
	boolean isGen;
	
	/**
	 * Constructor to initialize the object
	 * @param privateKeySize
	 * @param publicKeySize
	 */
	public ECKeyPair(short privateKeySize, short publicKeySize)
	{
		ePrivateKey = new byte[privateKeySize];
		pubKey = new byte[publicKeySize];
		
		isGen = false;
	}
	
	/**
	 * Set the Keys
	 * @param privateKey
	 * @param privOff
	 * @param privLength
	 * @param publicKey
	 * @param pubOff
	 * @param pubLength
	 */
	public void setKey(byte[] privateKey, short privateKeyOff, short privateKeyLength, 
			byte[] publicKey, short publicKeyOff, short publicKeyLength)
	{
		if(isGen)
		{
			CardRuntimeException.throwIt(StatusCodes.KEY_IS_IN_USE);
		}
		
		if((publicKeyLength != (short) pubKey.length) || (privateKeyLength != (short) ePrivateKey.length))
		{
			CardRuntimeException.throwIt(StatusCodes.WRONG_PRIVATE_KEY_LENGTH);
		}
		
		Util.arrayCopy(privateKey, privateKeyOff, ePrivateKey, (short) 0, privateKeyLength);
		Util.arrayCopy(publicKey, publicKeyOff, pubKey, (short) 0, publicKeyLength);
		isGen = true;
	}
	
	/**
	 * returns the private key in encrypted form
	 * @param dest
	 * @param destOff
	 * @return length of the private key
	 */
	public short getPrivateKey(byte[] dest, short destOff)
	{
		if(!isGen)
		{
			return 0;
		}
		
		Util.arrayCopy(ePrivateKey, (short) 0, dest, destOff, (short) ePrivateKey.length);
		return (short) ePrivateKey.length;
	}
	
	/**
	 * returns the private key length
	 */
	public short getPrivateKeySize()
	{
		return (short) ePrivateKey.length;
	}
	
	/**
	 * returns the public key in 
	 * @param dest
	 * @param destOff
	 * @return length of the public key
	 */
	public short getPublicKey(byte[] dest, short destOff)
	{
		if(!isGen)
		{
			return 0;
		}
		
		Util.arrayCopy(pubKey, (short) 0, dest, destOff, (short) pubKey.length);
		return (short) pubKey.length;
	}
	
	/**
	 * Get PubKey Size
	 */
	public short getPublicKeySize()
	{
		return (short) pubKey.length;
	}
	
	/**
	 * Is valid - whether generated or not
	 */
	public boolean isValid()
	{
		return isGen;
	}
	
	/**
	 * Delete this key pair
	 */
	public void clear()
	{
		isGen = false;
		Util.arrayFillNonAtomic(ePrivateKey, (short) 0, (short) ePrivateKey.length, (byte) 0);
		Util.arrayFillNonAtomic(pubKey, (short) 0, (short) pubKey.length, (byte) 0);
	}
}
