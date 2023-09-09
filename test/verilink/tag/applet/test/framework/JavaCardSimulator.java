package verilink.tag.applet.test.framework;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import javacard.framework.AID;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorRuntime;

import verilink.tag.applet.AppletInstructions;
import verilink.tag.applet.VerilinkApplet;


public class JavaCardSimulator implements JavaCard {
	private Simulator simulator;
	
	public JavaCardSimulator(byte[] appletID)
	{
		simulator = new Simulator();
		AID aid = new AID(appletID, (short) 0, (byte) appletID.length);
		simulator.installApplet(aid,  VerilinkApplet.class);
		simulator.selectApplet(aid);
	}
	
	@Override
	public ResponseAPDU transmit(CommandAPDU command)
	{
		return new ResponseAPDU(simulator.transmitCommand(command.getBytes()));
	}
}
