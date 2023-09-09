package verilink.tag.applet;

/**
 * Error and Status codes for the Verilink Tag Applet
 * 
 * @author isaacdubuque
 */
public interface StatusCodes {
	
	/**
	 * Key Generation Failed
	 */
	short KEY_GEN_FAILED = (short) 0x6A84;
	
	/**
	 * Get Key Info Failed
	 */
	short KEY_GET_FAILED = (short) 0x6A88;
	
	/**
	 * Signature Failure
	 */
	short SIGNATURE_FAILED = (short) 0x6982;
	
	/**
	 * Key In Use
	 */
	short KEY_IS_IN_USE = (short) 0x6283;
	
	/**
	 * Wrong Private Key Length
	 */
	short WRONG_PRIVATE_KEY_LENGTH = (short) 0x6702;
	
	/**
	 * Wrong Public Key Length
	 */
	short WRONG_PUBLIC_KEY_LENGTH = (short) 0x6703;
}
