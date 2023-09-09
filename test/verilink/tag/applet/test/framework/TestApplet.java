package verilink.tag.applet.test.framework;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/* import the classes */
import verilink.tag.applet.test.tests.KeyGenerateTest;
import verilink.tag.applet.test.tests.PublicKeyTest;
import verilink.tag.applet.test.tests.SignatureTest;

@RunWith(Suite.class)
@SuiteClasses({ KeyGenerateTest.class, PublicKeyTest.class, SignatureTest.class })
public class TestApplet {

}
