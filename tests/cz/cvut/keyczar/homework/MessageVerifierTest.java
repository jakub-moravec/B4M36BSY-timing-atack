package cz.cvut.keyczar.homework;


import org.junit.Before;
import org.junit.Test;

import java.io.*;

import static org.junit.Assert.assertEquals;

public class MessageVerifierTest {

	private static final String MESSAGE = CreateSignedFile.MESSAGE;
	private static final byte[] GOOD_PREAMBLE
			= new byte[]{0, 92, 17, -97, -123};
	private static final byte[] GOOD_SIGNATURE = new byte[]{
			-10, -53, -115, -79, -8, 62, -112, -10, 115, -4, -85,
			15, 95, 84, 58, -13, 22, 117, -114, -125
	};

	private MessageVerifier messageVerifier;
	private BufferedReader fromVerifier;
	private OutputStream toVerifier;

	@Before
	public void setUp() throws Throwable {
		PipedInputStream pipeFromVerifier = new PipedInputStream();
		PipedOutputStream pipeToVerifier = new PipedOutputStream();

		fromVerifier = new BufferedReader(
				new InputStreamReader(pipeFromVerifier));
		toVerifier = new BufferedOutputStream(pipeToVerifier);

		messageVerifier = new MessageVerifier(
				new PipedOutputStream(pipeFromVerifier),
				new PipedInputStream(pipeToVerifier)
		);
		messageVerifier.initialize();
		startMessageVerifierThread();
		assertResultFromVerifierIs("READY");
	}

	@Test
	public void gotByeOnClose() throws Throwable {
		toVerifier.close();
		assertResultFromVerifierIs("BYE");
	}

	@Test
	public void gotErrorOnInvalid() throws Throwable {
		writeToVerifier(new byte[5], new byte[20]);
		assertResultFromVerifierIs(
				"ERROR: Key with hash identifier 0 not found");
	}

	@Test
	public void gotNotOkOnBadSignature() throws Throwable {
		writeToVerifier(GOOD_PREAMBLE, new byte[20]);
		assertResultFromVerifierIs("NOT OK");
	}

	@Test
	public void gotOkOnGoodSignature() throws Throwable {
		writeToVerifier(GOOD_PREAMBLE, GOOD_SIGNATURE);
		assertResultFromVerifierIs("OK");
	}

	@Test
	public void canProcessMoreThanOneRequest() throws Throwable {
		for (int i = 0; i < 5; i++) {
			if (i % 2 == 0) {
				gotOkOnGoodSignature();
			}
			else {
				gotNotOkOnBadSignature();
			}
		}
	}

	private void writeToVerifier(byte[] preamble, byte[] hMAC)
			throws IOException {
		toVerifier.write(MESSAGE.getBytes());
		toVerifier.write('\0');
		toVerifier.write(preamble);
		toVerifier.write(hMAC);
		toVerifier.flush();
	}

	private void assertResultFromVerifierIs(String expected)
			throws IOException {
		assertEquals(expected, fromVerifier.readLine());
	}

	private void startMessageVerifierThread() {
		Thread messageVerifierThread = new Thread(messageVerifier);
		messageVerifierThread.setDaemon(true);
		messageVerifierThread.start();
	}

}
