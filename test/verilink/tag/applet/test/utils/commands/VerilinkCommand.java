package verilink.tag.applet.test.utils.commands;

/* javacard */
import javax.smartcardio.CommandAPDU;

public interface VerilinkCommand {

		public CommandAPDU getCommand();
		
		public String getName();
}
