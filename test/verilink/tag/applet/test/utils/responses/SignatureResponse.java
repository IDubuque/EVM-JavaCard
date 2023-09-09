package verilink.tag.applet.test.utils.responses;

import verilink.tag.applet.test.utils.logging.Logging;

/* Java math */
import java.math.BigInteger;

/* ASN1 decoding */
import org.bouncycastle.asn1.*;

/* Exceptions */
import java.io.IOException;

/* ECPublicKey */
import java.security.interfaces.ECPublicKey;

/* Java Security */
import java.security.Signature;

/* Exceptions */
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.io.UnsupportedEncodingException;

public class SignatureResponse {
	
	byte[] signature;
	int sigSize;
	BigInteger r, s;
	byte[] globalSigCounter;
	byte[] sigCounter;
	
	boolean isVerbose;
	
	private static final int GLOBAL_SIG_COUNTER_SIZE = 4;
	private static final int SIG_COUNTER_SIZE = 4;
	private static final int ECDSA_POINT_SIZE = 32;
	
	public SignatureResponse()
	{
		this(false);
	}
	
	public SignatureResponse(boolean verbose)
	{
		isVerbose = verbose;
		
		/* signature - wait to allocate buffer */
		globalSigCounter = new byte[GLOBAL_SIG_COUNTER_SIZE];
		sigCounter = new byte[SIG_COUNTER_SIZE];
	}
	
	public SignatureResponse(byte[] bytes)
	{
		this(false);
		parseResponse(bytes);
	}
	
	public SignatureResponse(byte[] bytes, boolean verbose)
	{
		this(verbose);
		parseResponse(bytes);
	}
	
	public void parseResponse(byte[] bytes)
	{
		boolean derDecode = true;
		int idx = 0;
		System.arraycopy(bytes, idx, globalSigCounter, 0, GLOBAL_SIG_COUNTER_SIZE);
		idx += GLOBAL_SIG_COUNTER_SIZE;
		
		System.arraycopy(bytes, idx, sigCounter, 0, SIG_COUNTER_SIZE);
		idx += SIG_COUNTER_SIZE;
		
		sigSize = bytes.length - GLOBAL_SIG_COUNTER_SIZE - SIG_COUNTER_SIZE;
		signature = new byte[sigSize];
		System.arraycopy(bytes, idx, signature, 0, sigSize);
		
		try
		{
			decodeDERSignature();
		}
		catch(Exception e)
		{
			derDecode = false;
			System.out.println("[ERROR]: " + e.getMessage());
		}
		
		
		if(isVerbose)
		{
			System.out.println("GlobalSigCounter: " + Logging.getHexString(globalSigCounter, 0, GLOBAL_SIG_COUNTER_SIZE));
			System.out.println("SigCounter: " + Logging.getHexString(sigCounter, 0, SIG_COUNTER_SIZE));
			System.out.println("Signature: " + Logging.getHexString(signature, 0, sigSize));
			
			if(derDecode)
			{
				System.out.println("R: " + r.toString());
				System.out.println("S: " + s.toString());
			}
		}
	}
	
	/**
	 * Trim Zeros
	 */
    private static byte[] trimZeroes(byte[] b) {
        int i = 0;
        while ((i < b.length - 1) && (b[i] == 0)) {
            i++;
        }
        if (i == 0) {
            return b;
        }
        byte[] t = new byte[b.length - i];
        System.arraycopy(b, i, t, 0, t.length);
        return t;
    }
    
    /**
     * Decode DER Signature
     */
    private void decodeDERSignature() throws Exception
    {
    	try
    	{
	    	ASN1InputStream decoder = new ASN1InputStream(signature);
	    	DLSequence seq = (DLSequence) decoder.readObject();
	    	ASN1Integer ar, as;
	    	
	    	ar = (ASN1Integer) seq.getObjectAt(0);
	    	as = (ASN1Integer) seq.getObjectAt(1);
		    
	    	r = ar.getValue();
	    	s = as.getValue();
    	}
    	catch(Exception e)
    	{
    		throw new Exception("Decode DER Signature failure: " + e.getMessage());
    	}
    }
    
    public boolean verifySignature(byte[] challenge, ECPublicKey pubKey)
    	throws Exception
    {
    	boolean isValid;
    	
    	try
    	{
	    	Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
	    	ecdsaVerify.initVerify(pubKey);
	    	ecdsaVerify.update(challenge);
	    	isValid = ecdsaVerify.verify(signature);
    	}
    	catch(Exception e)
    	{
    		throw new Exception("Signature verification failure: " + e.getMessage());
    	}
    	
    	return isValid;
    }
    
    public byte[] getSignature()
    {
    	return signature;
    }
    
    public BigInteger getR() {
    	return r;
    }
    
    public BigInteger getS()
    {
    	return s;
    }
}

/*	
    public static byte[] trimZeroes(byte[] b) {
        int i = 0;
        while ((i < b.length - 1) && (b[i] == 0)) {
            i++;
        }
        if (i == 0) {
            return b;
        }
        byte[] t = new byte[b.length - i];
        System.arraycopy(b, i, t, 0, t.length);
        return t;
    }
    
    	public static byte[] decodeDERSignature(byte[] signature) throws IOException
	{
		ASN1InputStream decoder = new ASN1InputStream(signature);
		DLSequence seq = (DLSequence) decoder.readObject();
		ASN1Integer r, s;
	
		r = (ASN1Integer) seq.getObjectAt(0);
		s = (ASN1Integer) seq.getObjectAt(1);
		
		byte[] bR = trimZeroes(r.getValue().toByteArray());
		byte[] bS = trimZeroes(s.getValue().toByteArray());
		
		
		int k = Math.max(bR.length, bS.length);
        // r and s each occupy half the array
        byte[] res = new byte[k << 1];
        System.arraycopy(bR, 0, res, k - bR.length, bR.length);
        System.arraycopy(bS, 0, res, res.length - bS.length, bS.length);
        return res;
	}
	
		public static boolean verifySignature(byte[] challenge, ECPublicKey pubKey, byte[] signature)
	throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException
	{
		Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
		ecdsaVerify.initVerify(pubKey);
		ecdsaVerify.update(challenge);
		return ecdsaVerify.verify(signature);
	}
	
*/







