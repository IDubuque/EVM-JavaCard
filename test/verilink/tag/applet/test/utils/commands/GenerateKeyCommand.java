package verilink.tag.applet.test.utils.commands;

/* Applet Instructions */
import verilink.tag.applet.AppletInstructions;

/* Smart Cardio */
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.CardException;

public class GenerateKeyCommand implements VerilinkCommand {
	
	CommandAPDU generateKeyInstruction;
	
	private static final int EXPECTED_RESPONSE_LENGTH = 1;
	public static final String name = "Generate Key";
	
	public GenerateKeyCommand() {
		generateKeyInstruction = new CommandAPDU(
			AppletInstructions.VERILINK_TAG_CLA,
			AppletInstructions.INS_GENERATE_KEY, 
			0,
			0,
			EXPECTED_RESPONSE_LENGTH
		);
	}
	
	@Override
	public String getName() 
	{
		return name;
	}
	
	@Override
	public CommandAPDU getCommand()
	{
		return generateKeyInstruction;
	}
}
