package verilink.tag.applet.test.utils.commands;

/* Applet Instructions */
import verilink.tag.applet.AppletInstructions;

/* Smart Cardio */
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.CardException;

public class SignatureCommand implements VerilinkCommand {
	
	CommandAPDU getSignatureInstruction;
	
	private static final int DATA_LENGTH = 0x20;
	
	public static final String name = "Signature";
	
	public SignatureCommand(int keyHandle, byte[] challenge)
	{
		getSignatureInstruction = new CommandAPDU(
				AppletInstructions.VERILINK_TAG_CLA,
				AppletInstructions.INS_GENERATE_SIGNATURE,
				keyHandle,
				0,
				challenge, 
				DATA_LENGTH
		);
	}
	
	public String getName()
	{
		return name;
	}
	
	public CommandAPDU getCommand()
	{
		return getSignatureInstruction;
	}
}