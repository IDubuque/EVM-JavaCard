package verilink.tag.applet;

public interface AppletInstructions {
	
	/**
	 * CLA instruction class for Verilink Tag Applet
	 */
	byte VERILINK_TAG_CLA = (byte) 0x00;
	
	/**
	 * Generate Key Instruction.
	 */
	byte INS_GENERATE_KEY = (byte) 0x02;
	
	/**
	 * Get Key Info Instruction.
	 */
	byte INS_GET_KEY_INFO = (byte) 0x16;
	
	/**
	 * Generate Signature Instruction.
	 */
	byte INS_GENERATE_SIGNATURE = (byte) 0x18;
}