package verilink.tag.applet.test.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.CardException;

import org.junit.Test;

import javacard.framework.ISO7816;
import verilink.tag.applet.AppletInstructions;
import verilink.tag.applet.VerilinkApplet;
import verilink.tag.applet.test.tests.AppletTestBase;

/* bouncy castle for validating signatures */
import org.bouncycastle.asn1.x9.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.*;

/* java security */
import java.security.Signature;
import java.security.Security;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.ECPoint;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.SignatureException;
import java.io.UnsupportedEncodingException;
import java.util.Random;
import java.io.IOException;

/* commands */
import verilink.tag.applet.test.utils.commands.GenerateKeyCommand;
import verilink.tag.applet.test.utils.commands.GetPublicKeyCommand;
import verilink.tag.applet.test.utils.commands.SignatureCommand;
import verilink.tag.applet.test.utils.commands.VerilinkCommand;

/* responses */
import verilink.tag.applet.test.utils.responses.GenerateKeyResponse;
import verilink.tag.applet.test.utils.responses.GetPublicKeyResponse;
import verilink.tag.applet.test.utils.responses.SignatureResponse;

public class SignatureTest extends AppletTestBase {
	
	private boolean isVerbose;
	
	public SignatureTest() throws CardException
	{
		super();
		Security.addProvider(new BouncyCastleProvider());
		isVerbose = false;
	}
	
	/**
	 * Basic Signature Test
	 */
	@Test
	public void basicSignatureTest() throws 
		CardException, Exception
	{
		if(isVerbose)
		{
			System.out.println("Basic Signature Test");
		}

		byte[] challenge = new byte[32];
		
		/* send key generation command */
		GenerateKeyCommand genKeyCmd = new GenerateKeyCommand();
		ResponseAPDU response = sendCommand((VerilinkCommand) genKeyCmd, isVerbose);
		
		/* parse the response */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GenerateKeyResponse genKeyRsp = new GenerateKeyResponse(response.getData(), isVerbose);
		
		/* Send get public key command */
		GetPublicKeyCommand getPubKeyCmd = new GetPublicKeyCommand(genKeyRsp.getKeyHandle());
		response = sendCommand((VerilinkCommand) getPubKeyCmd, isVerbose);
		
		/* parse response and assert */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GetPublicKeyResponse getPubKeyRsp = new GetPublicKeyResponse(response.getData(), isVerbose);
		
		/* Generate Challenge */
		new Random().nextBytes(challenge);
		
		/* send signature command */
		SignatureCommand sigCmd = new SignatureCommand(genKeyRsp.getKeyHandle(), challenge);
		response = sendCommand((VerilinkCommand) sigCmd, isVerbose);
		
		/* parse response and assert */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		SignatureResponse sigRsp = new SignatureResponse(response.getData(), isVerbose);
		assertTrue(sigRsp.verifySignature(challenge, getPubKeyRsp.getECPublicKey()));
	}
	
	/**
	 * Generate Multiple Signatures Test
	 */
	@Test
	public void multipleSignatureTest() throws 
		CardException, Exception
	{
		if(isVerbose)
		{
			System.out.println("Basic Signature Test");
		}

		byte[] challenge = new byte[32];
		
		/* send key generation command */
		GenerateKeyCommand genKeyCmd = new GenerateKeyCommand();
		ResponseAPDU response = sendCommand((VerilinkCommand) genKeyCmd, isVerbose);
		
		/* parse the response */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GenerateKeyResponse genKeyRsp = new GenerateKeyResponse(response.getData(), isVerbose);
		
		/* Send get public key command */
		GetPublicKeyCommand getPubKeyCmd = new GetPublicKeyCommand(genKeyRsp.getKeyHandle());
		response = sendCommand((VerilinkCommand) getPubKeyCmd, isVerbose);
		
		/* parse response and assert */
		assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
		GetPublicKeyResponse getPubKeyRsp = new GetPublicKeyResponse(response.getData(), isVerbose);
		
		/* Generate Challenge */
		new Random().nextBytes(challenge);
		
		SignatureCommand sigCmd;
		SignatureResponse sigRsp;
		
		for(int i = 0; i < 10; i++)
		{
			/* Generate Challenge */
			new Random().nextBytes(challenge);
			
			/* send signature command */
			sigCmd = new SignatureCommand(genKeyRsp.getKeyHandle(), challenge);
			response = sendCommand((VerilinkCommand) sigCmd, isVerbose);
			
			/* parse response and assert */
			assertTrue(checkStatusCode(response, ISO7816.SW_NO_ERROR, isVerbose));
			sigRsp = new SignatureResponse(response.getData(), isVerbose);
			assertTrue(sigRsp.verifySignature(challenge, getPubKeyRsp.getECPublicKey()));
		}
	}
}