# EVM Compatible JavaCard
The JavaCard uses EC SECP256K1 to generate secure keys and sign messages


Setting up the build environment:

1.) Clone the repo
2.) Install JDK 11
3.) Install ant
	a.) brew install ant
	b.) in .zshrc / .bashrc add the following:
		# SET APACHE ANT VERSIONS
		export ANT_PATH="/opt/homebrew/opt/ant"
		export ANT_HOME="${ANT_PATH}/libexec"
		export PATH="${ANT_PATH}/bin:$PATH"
4.) Ready to build


Building the Java Applet:
1.) ant build
2.) javacard.cap will be exported to Verilink-Tag/bin/cap/javacard.cap

Running the test suite:
1.) ant test
2.) the test build will be exported to Verilink-Tag/build
3.) ant will run the full test suite and report errors


Cleaning the build
1.) ant clean
2.) Verilink-Tag/build and Verilink-Tag/bin will be removed
