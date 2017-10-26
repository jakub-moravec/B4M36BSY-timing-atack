package cz.cvut.keyczar.homework;

public class VerificationServer {

	public static void main(String[] arguments) {		
		Runnable messageVerifier = createMessageVerifier();
		messageVerifier.run();
	}

	private static Runnable createMessageVerifier() {
		MessageVerifier messageVerifier;
		try {
			messageVerifier = new MessageVerifier(System.out, System.in);
			messageVerifier.initialize();
			return messageVerifier;
		}
		catch (Throwable t) {
			System.err.println("Can't load Verifier: " + t.getMessage());
			System.exit(1);
			return null;
		}
	}

}
