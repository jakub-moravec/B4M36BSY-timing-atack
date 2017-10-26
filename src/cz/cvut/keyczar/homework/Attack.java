package cz.cvut.keyczar.homework;

import cz.cvut.keyczar.Verifier;
import cz.cvut.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/**
 * Own implementation of timing attack.
 *
 * TODO
 *
 * @author moravja8
 */
public class Attack {

    private static final byte[] GOOD_PREAMBLE = {0, 92, 17, -97, -123};

    private static final int SIGNATURE_LENGTH = 20;
    private static final int PREAMBLE_LENGTH = 5;

    private static final int NUMBER_OF_TRIES = 50;

    private static final String DIFFICULTY = "HARDEST";

    private static Verifier verifier;
    private static byte[] message;

    private static byte[] correctSignature = new byte[SIGNATURE_LENGTH];

    public static void main(String[] args) throws KeyczarException {

        verifier = new Verifier("./keys");
        message = "Hello world".getBytes();

        System.setProperty("DIFFICULTY", DIFFICULTY);

        warmUp(250000);

        byte[] signature = new byte[SIGNATURE_LENGTH]; // signature to guess
        Arrays.fill(signature, Byte.MIN_VALUE);

        for (int i = 0; i < SIGNATURE_LENGTH; i++) {
            // todo if avg result time to low then i--
            findByte(signature, i);
        }

        System.out.println(verifier.verify(message, addPrefix(correctSignature)));
        System.out.println(Arrays.toString(addPrefix(correctSignature)));
    }

    public static long getMedian(long[] values) {
        Arrays.sort(values);
        long median;

        if (values.length % 2 == 0) {
            int i1 = (values.length / 2) - 1;
            int i2 = values.length / 2;
            median = (values[i1] + values[i2]) / 2;
        } else {
            median = (values.length / 2) + 1;
        }

        return  median;
    }


    private static void findByte(byte[] signature, int byteIndex) throws KeyczarException {
        byte maxDurationValue = 0;
        long maxDuration = Integer.MIN_VALUE;
        ByteBuffer messageBuffer = ByteBuffer.wrap(message);
        ByteBuffer signatureBuffer;

        for (int i = 0; i < 256; i++) {
            signature[byteIndex] = (byte) (i - Math.abs((int) Byte.MIN_VALUE));
            long[] durations = new long[NUMBER_OF_TRIES];
            long iterationStart;
            warmUp(NUMBER_OF_TRIES / 10);
            for (int n = 0; n < NUMBER_OF_TRIES; n++) {
                signatureBuffer = ByteBuffer.wrap(addPrefix(signature));

                messageBuffer.position(0);
                signatureBuffer.position(0);

                //verify(ByteBuffer.wrap(data), ByteBuffer.wrap(signature));
                iterationStart = System.nanoTime();
                verifier.verify(messageBuffer, signatureBuffer);
                durations[n] = (System.nanoTime() - iterationStart);
            }
            long actualDuration = getMedian(durations);

            if(actualDuration > maxDuration) {
                maxDuration = actualDuration;
                maxDurationValue = signature[byteIndex];
            }

            System.out.printf("Byte %d - input %d - duration %d .\n", byteIndex, (int) signature[byteIndex], actualDuration);
        }

        signature[byteIndex] = maxDurationValue;
        correctSignature[byteIndex] = maxDurationValue; // FIXME: 19.10.2017 drop
    }


    private static void warmUp(long tries) throws KeyczarException {
        byte[] signature = new byte[SIGNATURE_LENGTH];
        Random random = new Random();

        for (int i = 0; i < tries; i++) {
            random.nextBytes(signature);
            verifier.verify(message, addPrefix(signature));
        }
    }

    private static byte[] addPrefix (byte[] signature) {
        byte[] signatureWithPrefix = new byte[PREAMBLE_LENGTH + SIGNATURE_LENGTH];
        System.arraycopy(GOOD_PREAMBLE, 0, signatureWithPrefix, 0, PREAMBLE_LENGTH);
        System.arraycopy(signature, 0, signatureWithPrefix, PREAMBLE_LENGTH, SIGNATURE_LENGTH);
        return signatureWithPrefix;
    }
}
