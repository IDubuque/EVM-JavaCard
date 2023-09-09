package verilink.tag.applet.test.utils.responses;

public class GenerateKeyResponse {

	byte keyHandle;
	
	boolean isVerbose;
	
	private static final int KEY_HANDLE_SIZE = 1;
	
	public GenerateKeyResponse()
	{
		this(false);
	}
	
	public GenerateKeyResponse(boolean verbose)
	{
		isVerbose = verbose;
	}
	
	public GenerateKeyResponse(byte[] bytes, boolean verbose)
	{
		this(verbose);
		parseResponse(bytes);
	}
	
	public GenerateKeyResponse(byte[] bytes)
	{
		this(false);
		parseResponse(bytes);
	}
	
	public void parseResponse(byte[] bytes)
	{
		keyHandle = (byte) bytes[0];
		
		if(isVerbose)
		{
			System.out.println("KeyHandle: " + keyHandle);
		}
	}
	
	public int getKeyHandle() 
	{
		return (int) keyHandle;
	}
}
