package verilink.tag.applet.test.framework;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public interface JavaCard {

	public ResponseAPDU transmit(CommandAPDU command) throws CardException;
}