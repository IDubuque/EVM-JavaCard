package verilink.tag.applet.test.tests;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import javacard.framework.ISO7816;

import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.CardException;

import verilink.tag.applet.AppletInstructions;
import verilink.tag.applet.StatusCodes;

/* Test Framework */
import verilink.tag.applet.test.framework.JavaCard;
import verilink.tag.applet.test.framework.JavaCardSimulator;
import verilink.tag.applet.test.utils.commands.VerilinkCommand;

/**
 * Base class for Java Card applet tests.
 * 
 * @author isaacdubuque
 */
public abstract class AppletTestBase {
	
	/**
	 * The AID of the Verilink Tag Applet
	 */
	protected static final byte[] AID = { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 
			0x01, 0x0c, 0x06, 0x03, 0x01, 0x0c, 0x06, 0x01
	};
	
	
	/**
	 * CardChannel used to transmit commands
	 */
	protected JavaCard smartCard;
	
	/**
	 * Constructor. Init the simulator, select applet
	 * 
	 * @throws CardException
	 * @throws IOException
	 */
	public AppletTestBase() throws CardException
	{
		try
		{
			smartCard = new JavaCardSimulator(AID);
		}
		catch(Exception e)
		{
			System.out.println("Error Initiating Simulator: " + e.getMessage());
			throw new CardException("Simulator error");
		}
	}
	
	/**
	 * 
	 * Send Command
	 */
	public ResponseAPDU sendCommand(VerilinkCommand cmd, boolean verbose)
		throws CardException
	{
		if(verbose)
		{
			System.out.println("Sending command: " + cmd.getName());
		}
		
		return smartCard.transmit(cmd.getCommand());
	}
	
	public static boolean checkStatusCode(ResponseAPDU response, short statusCode, boolean verbose)
	{
		int responseStatusCode = (short) response.getSW();
		
		if(verbose)	
		{
			switch(responseStatusCode)
			{
				case ISO7816.SW_NO_ERROR:
					System.out.println("Status Code: Success");
					break;
				case StatusCodes.KEY_GEN_FAILED:
					System.out.println("Status Code: Failed key generation");
					break;
				case StatusCodes.KEY_GET_FAILED:
					System.out.println("Status Code: Failed to get public key");
					break;
				case StatusCodes.SIGNATURE_FAILED:
					System.out.println("Status Code: Failed to create signature");
					break;
				case StatusCodes.KEY_IS_IN_USE:
					System.out.println("Status Code: Key is in use");
					break;
				case StatusCodes.WRONG_PRIVATE_KEY_LENGTH:
					System.out.println("Status Code: Wrong Private key length");
					break;
				case StatusCodes.WRONG_PUBLIC_KEY_LENGTH:
					System.out.println("Status Code: Wrong Public Key Length");
					break;
				default:
					System.out.println("Status Code: " + responseStatusCode);
			}
		}
		
		return statusCode == responseStatusCode;
	}
	
	/**
	 * Checks if command was successful with ISO7816 response (0x9000)
	 * 
	 * @param response returned by APDU command
	 * @return boolean whether success
	 */
	public static boolean commandSuccessful(ResponseAPDU response)
	{
		int statusCode = (short) response.getSW();
		return ISO7816.SW_NO_ERROR == statusCode;
	}
	
	/**
	 * Checks if command had key generation failure
	 * 
	 * @param response returned by APDU command
	 * @return boolean whether success
	 */
	public static boolean commandKeyGenFailure(ResponseAPDU response)
	{
		int statusCode = (short) response.getSW();
		return StatusCodes.KEY_GEN_FAILED == statusCode;
	}
	
	/**
	 * Checks if get get failed
	 * 
	 * @param response 
	 */
	
	
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
