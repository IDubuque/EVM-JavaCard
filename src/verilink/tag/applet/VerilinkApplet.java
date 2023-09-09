package verilink.tag.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.RandomData;


/**
 * This is the Verilink Tag Applet. It stores a single private key
 * with corresponding public key in the NFT metadata. This cryptographically binds
 * the digital NFT with the physical item that contains the tag. 
 * The applet signs challenges to prove its authenticity and returns the signed data and public key.
 * 
 * @author isaacdubuque
 */
public class VerilinkApplet extends Applet {
	
	
	/**
	 * Size of the key store (default)
	 */
	public final static byte STORE_SIZE = (byte) 1;
	
	/**
	 * Key Store used for generating keys, storing keys, and signing with keys
	 */
	private KeyStore keyStore;
	
	/**
	 * Challenge Buffer for sha256 transaction hash
	 */
	private byte[] signMessage;
	
	/**
	 * Constructor. Initializes the memory for runtime. 
	 * Will be called by install method only
	 */
	private VerilinkApplet()
	{
		keyStore = new KeyStore(STORE_SIZE);
		signMessage = new byte[32];
		register();
	}
	
	/**
	 * Install the applet
	 * 
	 * @param bArray the array containing the installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of bArray
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
		throws ISOException
	{
		new VerilinkApplet();
	}
	
	/**
	 * Process APDU commands from Host
	 * 
	 * @param apdu the APDU command to process
	 */
	public void process(APDU apdu) throws ISOException
	{
		byte[] buffer = apdu.getBuffer();
		
		if(selectingApplet())
		{
			return;
		}
		
		/* Verify the CLA */
		if(buffer[ISO7816.OFFSET_CLA] != AppletInstructions.VERILINK_TAG_CLA)
		{
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		/* Process by INS */
		switch(buffer[ISO7816.OFFSET_INS]) 
		{
			case AppletInstructions.INS_GENERATE_KEY:
				generateKey(apdu, buffer);
				break;
			case AppletInstructions.INS_GET_KEY_INFO:
				getKeyInfo(apdu, buffer);
				break;
			case AppletInstructions.INS_GENERATE_SIGNATURE:
				generateSignature(apdu, buffer);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/**
	 * Generate a private / public key pair for the Tag
	 * returns the index of the generated key
	 * 
	 * <pre>
	 * INS: 0x02
	 * P1: 0x00 (RFU)
	 * P2: 0x00 (RFU)
	 * LE: 0x01
	 * </pre>
	 * 
	 * output
	 * data (1b): key handle
	 * SW1: 90
	 * SW2: 00
	 * 
	 */
	private void generateKey(APDU apdu, byte[] buffer)
	{
		if(((buffer[ISO7816.OFFSET_P1] & 0xFF) != 0x0) ||
			((buffer[ISO7816.OFFSET_P2] & 0XFF) != 0x0))
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		byte keyIndex = (byte) keyStore.generateKeyPair();
		
		buffer[0] = keyIndex;
		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}
	
	/**
	 * Get public key for the Tag
	 * 
	 * <pre>
	 * INS: 0x16
	 * P1: 0x00 (RFU)
	 * P2: 0x00 (RFU)
	 * LE: 0x01
	 * </pre>
	 */
	private void getKeyInfo(APDU apdu, byte[] buffer)
	{
		short p1 = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
		
		if((buffer[ISO7816.OFFSET_P2] & 0xFF) != 0x0)
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		short copyLength = Util.arrayFillNonAtomic(buffer, (short) 0, (short) 8, (byte) 0x69);
		short keyLength = keyStore.getPublicKey(p1, buffer, copyLength);
		apdu.setOutgoingAndSend((short) 0, (short) (copyLength + keyLength));
	}
	
	/**
	 * Generate Signature from a challenge
	 * 
	 * <pre>
	 * INS: 0x18
	 * </pre>
	 * 
	 */
	private void generateSignature(APDU apdu, byte[] buffer)
	{
		short copyLength, sigLength;
		short p1 = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
		short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
		
		if((buffer[ISO7816.OFFSET_P2] & 0xFF) != 0x0)
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		if(lc != 0x20)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		if (apdu.setIncomingAndReceive() != signMessage.length) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		/* copy message to be signed */
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, signMessage, (short) 0, lc);
		
		copyLength = Util.arrayFillNonAtomic(buffer, (short) 0, (short) 8, (byte) 0x69);
		
		sigLength = keyStore.signMessage(p1, signMessage, 
				(short) 0,
				lc, 
				buffer, 
				copyLength);
		
		apdu.setOutgoingAndSend((short) 0, (short) (sigLength + copyLength));
	}
}