package verilink.tag.applet.test.utils.commands;

/* Applet Instructions */
import verilink.tag.applet.AppletInstructions;

/* Smart Cardio */
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.CardException;

public class GetPublicKeyCommand implements VerilinkCommand {
	
	CommandAPDU getPublicKeyInstruction;
	
	public static final String name = "Public Key";
	
	public GetPublicKeyCommand(int keyHandle)
	{
		getPublicKeyInstruction = new CommandAPDU(
				AppletInstructions.VERILINK_TAG_CLA,
				AppletInstructions.INS_GET_KEY_INFO,
				keyHandle, 
				0, 
				0);
	}
	
	public String getName()
	{
		return name;
	}
	
	public CommandAPDU getCommand()
	{
		return getPublicKeyInstruction;
	}
}
