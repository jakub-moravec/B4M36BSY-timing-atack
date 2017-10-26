package cz.cvut.keyczar.homework;

import cz.cvut.keyczar.Signer;

import java.io.FileOutputStream;

public class CreateSignedFile {

	public static final String MESSAGE = "Hello world!";

	public static void main(String[] arguments) throws Throwable {
		Signer signer = new Signer("keys");
		byte[] sig = signer.sign(MESSAGE.getBytes());
		FileOutputStream fos = new FileOutputStream("testsig");
		fos.write(sig);
	}

}
