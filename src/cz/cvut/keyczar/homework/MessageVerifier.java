package cz.cvut.keyczar.homework;

import cz.cvut.keyczar.Verifier;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.Vector;

/** Verify incoming messages and HMACs in a loop.
 * The communications protocol is as follows:
 * <pre>
 * Verifier upon start: "READY"
 * loop:
 *   Client to Verifier: [message bytes][null byte][25 bytes of H-MAC]
 *   Verifier to Client: OK (when verification passes)
 *   Verifier to Client: NOT OK (when verification fails)
 *   Verifier to Client: ERROR: [error text] (when input is invalid)
 * end loop
 * Client to Verifier: (closes channel)
 * Verifier to Client: BYE (closes channel)
 * </pre>
 */
public class MessageVerifier implements Runnable {

	private Verifier keyCzarVerifier = null;
	private PrintStream outputStream;
	private InputStream inputStream;

	/** Create an instance with input/output channels.
	 *
	 * @param outputStream output verification results
	 * @param inputStream input messages and HMACs
	 */
	public MessageVerifier(OutputStream outputStream, InputStream inputStream) {
		this.outputStream = new PrintStream(outputStream);
		this.inputStream = inputStream;
	}

	/** Readies the instance (initializes keys etc.)
	 *
	 * @throws Throwable on error
	 */
	public void initialize() throws Throwable {
		keyCzarVerifier = new Verifier("keys");
		outputStream.println("READY");
	}

	/** Runs the instance
	 *
	 */
	public void run() {
		verifyMessages();
	}

	private void verifyMessages() {
		while (true) {
			try {
				verifyOne();
			}
			catch (EOF e) {
				outputStream.println("BYE");
				return;
			}
			catch (Throwable t) {
				outputStream.println("ERROR: " + t.getMessage());
			}
		}
	}

	private void verifyOne() throws Throwable {
		byte[] message = readNullTerminatedMessage();
		byte[] hMAC = readHMAC();
		boolean result = keyCzarVerifier.verify(message, hMAC);
		outputStream.println(result ? "OK" : "NOT OK");
	}

	private byte[] readNullTerminatedMessage() throws Throwable {
		List<Byte> message = new Vector<Byte>();
		while (true) {
			byte b = byteFromInput();
			if (b == 0) {
				break; // don't append the null byte
			}
			message.add(b);
		}
		return listToByteArray(message);
	}

	private byte[] readHMAC() throws Throwable {
		byte[] hMAC = new byte[25];
		for (int i = 0; i < 25; i++) {
			hMAC[i] = byteFromInput();
		}
		return hMAC;
	}

	private static byte[] listToByteArray(List<Byte> list) {
		byte[] array = new byte[list.size()];
		for (int i = 0; i < array.length; i++) {
			array[i] = list.get(i);
		}
		return array;
	}

	private byte byteFromInput() throws Throwable {
		int i = inputStream.read();
		if (i < 0) {
			throw new EOF();
		}
		return (byte) i;
	}

	private class EOF extends Throwable {

	}

}
