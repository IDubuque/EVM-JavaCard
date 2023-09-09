package verilink.tag.applet.test.tests;

import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CardException;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import javacard.framework.ISO7816;

/* commands */
import verilink.tag.applet.test.utils.commands.GenerateKeyCommand;
import verilink.tag.applet.test.utils.commands.GetPublicKeyCommand;
import verilink.tag.applet.test.utils.commands.VerilinkCommand;

/* responses */
import verilink.tag.applet.test.utils.responses.GenerateKeyResponse;
import verilink.tag.applet.test.utils.responses.GetPublicKeyResponse;

public class PublicKeyTest extends AppletTestBase {

	private boolean isVerbose;
	public PublicKeyTest() throws CardException
	{
		super();
		isVerbose = false;
	}
	
	/**
	 * Test Get Public Key from handle
	 * 
	 * @throws CardException
	 */
	@Test
	public void basicGetPublicKeyTest() throws CardException
	{
		if(isVerbose)
		{
			System.out.println("Basic Public Key Get Test");
		}
		
		/* send key generation command */
		GenerateKeyCommand genKeyCmd = new GenerateKeyCommand();
		ResponseAPDU response = sendCommand((VerilinkCommand) genKeyCmd, isVerbose);
		
		/* parse response and assert */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GenerateKeyResponse genKeyRsp = new GenerateKeyResponse(response.getData(), isVerbose);
		assertTrue(genKeyRsp.getKeyHandle() == 0);
		
		/* Send get public key command */
		GetPublicKeyCommand getPubKeyCmd = new GetPublicKeyCommand(genKeyRsp.getKeyHandle());
		response = sendCommand((VerilinkCommand) getPubKeyCmd, isVerbose);
		
		/* parse response and assert */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GetPublicKeyResponse getPubKeyRsp = new GetPublicKeyResponse(response.getData(), isVerbose);

	}
}
