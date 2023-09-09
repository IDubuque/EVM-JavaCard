package verilink.tag.applet.test.tests;

import static org.junit.Assert.assertTrue;

import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CardException;

import org.junit.Test;

import javacard.framework.ISO7816;
import verilink.tag.applet.StatusCodes;

/* commands */
import verilink.tag.applet.test.utils.commands.GenerateKeyCommand;
import verilink.tag.applet.test.utils.commands.VerilinkCommand;

/* responses */
import verilink.tag.applet.test.utils.responses.GenerateKeyResponse;

public class KeyGenerateTest extends AppletTestBase {
	
	private boolean isVerbose;
	public KeyGenerateTest() throws CardException
	{
		super();
		isVerbose = false;
	}
	
	/**
	 * Test Key Generation function
	 * 
	 * @throws CardException
	 */
	@Test
	public void basicGenerateKeyTest() throws CardException {
		if(isVerbose)
		{
			System.out.println("Basic Test Key Generation");
		}
		
		/* Send key generation command */
		GenerateKeyCommand keyCmd = new GenerateKeyCommand();
		ResponseAPDU response = sendCommand((VerilinkCommand) keyCmd, isVerbose);
		
		/* parse response and assert */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GenerateKeyResponse keyRsp = new GenerateKeyResponse(response.getData(), isVerbose);
		assertTrue(keyRsp.getKeyHandle() == 0);
	}
	
	/**
	 * Tests Max Key Generation and assert if another 
	 * key generation is attempted
	 * 
	 * @throws CardException
	 */
	@Test
	public void generateMaxKeyTest() throws CardException
	{
		if(isVerbose)
		{
			System.out.println("Test Max Key Generation");
		}
		
		/* Send key generation command */
		GenerateKeyCommand keyCmd = new GenerateKeyCommand();
		ResponseAPDU response = sendCommand((VerilinkCommand) keyCmd, isVerbose);
		
		/* parse response and assert */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GenerateKeyResponse keyRsp = new GenerateKeyResponse(response.getData(), isVerbose);
		assertTrue(keyRsp.getKeyHandle() == 0);
		
		
		response = sendCommand((VerilinkCommand) keyCmd, isVerbose);
		
		/* ensure error code */
		assertTrue(checkStatusCode(response, StatusCodes.KEY_GEN_FAILED, isVerbose));
	}
}
