package verilink.tag.applet.test.utils.logging;

public class Logging {
	/**
	 * Convert bytes to hex
	 */
	public static String getHexString(byte[] data, int offset, int length) {
		StringBuilder builder = new StringBuilder();
		
		for(int i = offset; i < (offset + length) && i < data.length; i++)
		{
			builder.append(String.format("%02X", data[i]));
		}
		
		return builder.toString();
	}
	
}
