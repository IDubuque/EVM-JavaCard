package verilink.tag.applet.test.utils.responses;

import verilink.tag.applet.test.utils.logging.Logging;

/* math */
import java.math.BigInteger;

/* Java Security Imports */
import java.security.interfaces.ECPublicKey;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;


/* java security EC spec */
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECGenParameterSpec;

/* Exceptions */
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class GetPublicKeyResponse {
	
	byte[] x;
	byte[] y;
	byte[] publicKey;
	byte[] globalSigCounter;
	byte[] sigCounter;
	
	boolean isVerbose;
	
	private static final int GLOBAL_SIG_COUNTER_SIZE = 4;
	private static final int SIG_COUNTER_SIZE = 4;
	private static final int PUBLIC_KEY_SIZE = 65;
	private static final int ECDSA_POINT_SIZE = 32;
	
	public GetPublicKeyResponse()
	{
		this(false);
	}
	
	public GetPublicKeyResponse(boolean verbose)
	{
		isVerbose = verbose;
		
		globalSigCounter = new byte[GLOBAL_SIG_COUNTER_SIZE];
		sigCounter = new byte[SIG_COUNTER_SIZE];
		x = new byte[ECDSA_POINT_SIZE];
		y = new byte[ECDSA_POINT_SIZE];
		publicKey = new byte[PUBLIC_KEY_SIZE];
	}
	
	public GetPublicKeyResponse(byte[] bytes, boolean verbose)
	{
		this(verbose);
		parseResponse(bytes);
	}
	
	public GetPublicKeyResponse(byte[] bytes)
	{
		this(false);
		parseResponse(bytes);
	}
	
	public void parseResponse(byte[] bytes)
	{
		int idx = 0;
		System.arraycopy(bytes, idx, globalSigCounter, 0, GLOBAL_SIG_COUNTER_SIZE);
		idx += GLOBAL_SIG_COUNTER_SIZE;
		
		System.arraycopy(bytes, idx, sigCounter, 0, SIG_COUNTER_SIZE);
		idx += SIG_COUNTER_SIZE;
		
		System.arraycopy(bytes, idx, publicKey, 0, PUBLIC_KEY_SIZE);
		idx += 1;
		
		System.arraycopy(bytes, idx, x, 0, ECDSA_POINT_SIZE);
		idx += ECDSA_POINT_SIZE;
		System.arraycopy(bytes, idx, y, 0, ECDSA_POINT_SIZE);
		
		if(isVerbose)
		{
			System.out.println("GlobalSigCounter: " + Logging.getHexString(globalSigCounter, 0, globalSigCounter.length));
			System.out.println("SigCounter: " + Logging.getHexString(sigCounter, 0, sigCounter.length));
			System.out.println("PublicKey: " + Logging.getHexString(publicKey, 0, PUBLIC_KEY_SIZE));
			System.out.println("Pubkey ecPoint X: " + Logging.getHexString(x, 0, ECDSA_POINT_SIZE));
			System.out.println("Pubkey ecPoint Y: " + Logging.getHexString(y, 0, ECDSA_POINT_SIZE));
		}
	}
	
	public byte[] getX()
	{
		return x;
	}
	
	public byte[] getY()
	{
		return y;
	}
	
	/**
	 * Recover EC Public Key
	 */
	
	public ECPublicKey getECPublicKey()
		throws Exception
	{
		ECPoint pubKeyPoint;
		AlgorithmParameters algParams;
		ECParameterSpec ecParams;
		ECPublicKeySpec pubSpec;
		KeyFactory kf;
		ECPublicKey ecPubKey;
		
		try
		{		
			/* convert x, y coords to ecPoint */
			pubKeyPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			
			algParams = AlgorithmParameters.getInstance("EC", "BC");
			algParams.init(new ECGenParameterSpec("secp256k1"));
			ecParams = algParams.getParameterSpec(ECParameterSpec.class);
			pubSpec = new ECPublicKeySpec(pubKeyPoint, ecParams);
			kf = KeyFactory.getInstance("EC");
			ecPubKey = (ECPublicKey) kf.generatePublic(pubSpec);
		}
		catch(Exception e)
		{
			throw new Exception("EC Public Key conversion failure: " + e.getMessage());
		}
		
		return ecPubKey;
	}
}

/* *
 * ORIGINAL CODE

	public static ECPublicKey recoverECPubKey (byte[] x, byte[] y) 
		throws NoSuchProviderException, NoSuchAlgorithmException,
		InvalidKeySpecException, InvalidParameterSpecException
	{
		ECPoint pubPoint;
		AlgorithmParameters algParams;
		ECParameterSpec ecParams;
		ECPublicKeySpec pubSpec;
		KeyFactory kf;
		
		pubPoint = new ECPoint(new BigInteger(1, x),new BigInteger(1, y));
		
		algParams = AlgorithmParameters.getInstance("EC", "BC");
        algParams.init(new ECGenParameterSpec("secp256k1"));
        ecParams = algParams.getParameterSpec(ECParameterSpec.class);
        pubSpec = new ECPublicKeySpec(pubPoint, ecParams);
        kf = KeyFactory.getInstance("EC");
	        
		return (ECPublicKey) kf.generatePublic(pubSpec);
	}
 * 
 */