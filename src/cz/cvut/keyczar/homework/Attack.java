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

    private static final String DIFFICULTY = "HARD";

    private static Verifier verifier;
    private static byte[] message;
    private static long[] avgByteDurations;
    private static byte[] signature;
    private static int[] findByteTries;

    public static void main(String[] args) throws KeyczarException {

        verifier = new Verifier("./keys");
        message = "Hello world".getBytes();

        System.setProperty("DIFFICULTY", DIFFICULTY);

        warmUp(250000);

        avgByteDurations = new long[SIGNATURE_LENGTH];
        signature = new byte[SIGNATURE_LENGTH];
        findByteTries = new int[SIGNATURE_LENGTH];
        Arrays.fill(signature, Byte.MIN_VALUE);

        for (int i = 0; i < SIGNATURE_LENGTH; i++) {
            findByte(i);

            // fallback if we made bad guess
            // if avg result time too low then redo last iteration
            // shifted by 2 so we skip first 2 iterations
            if (i>2) {
                long durationDelta = avgByteDurations[i] - avgByteDurations[i - 1];
                long avgDelta = getAverageDeltaInInterval(Math.max(0, i - 4), Math.max(0, i - 2), avgByteDurations);
                if (durationDelta < avgDelta / 2) { // we expect the delta of times will decrease, that is why we take avg / 2 as threshold
                    i -= 2; // we have to return to pre-previous iteration since it is the one, where the error is
                }
            }

            // iff only last byte is wrong, redo only last iteration
            if (i == SIGNATURE_LENGTH - 1 && !verifier.verify(message, addPrefix(signature))) {
                i--;
            }

            System.out.print("Byte " + i + " - output [");
            for (int j = 0; j <= i; j++) {
                System.out.print(signature[j]);
                if (j < i) {
                    System.out.print(", ");
                }
            }
            System.out.println("]");
        }

        System.out.println(verifier.verify(message, addPrefix(signature)));
        System.out.println(Arrays.toString(addPrefix(signature)));
    }

    /**
     * Counts median of given values.
     * Reorders input.
     * @param values input values
     * @return median
     */
    private static long getMedian(long[] values) {
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

    /**
     * Counts average delta between items i and i + 1. Zero values are not counted.
     * @param values input values
     * @param start start of interval of counted values
     * @return average delta
     */
    private static long getAverageDeltaInInterval(int start, int end, long[] values) {
        int itemsCounted = 0;
        long accumulator = 0;

        for (int i = start; i < end; i++) {
            int j = i + 1;
            if (j < SIGNATURE_LENGTH && values[j] > 0) {
                accumulator += values[j] - values[i];
                itemsCounted++;
            } else {
                break;
            }
        }

        return Math.round(accumulator / (double) itemsCounted);
    }


    /**
     * TODO
     * @param byteIndex index of byte that should be guessed
     * @throws KeyczarException ops
     */
    private static void findByte(int byteIndex) throws KeyczarException {
        byte maxDurationValue = 0;
        long maxDuration = Integer.MIN_VALUE;
        ByteBuffer messageBuffer = ByteBuffer.wrap(message);
        ByteBuffer signatureBuffer;
        avgByteDurations[byteIndex] = 0;
        findByteTries[byteIndex]++;

        for (int i = 0; i < 256; i++) {
            signature[byteIndex] = (byte) (i - Math.abs((int) Byte.MIN_VALUE));
            long[] durations = new long[NUMBER_OF_TRIES];
            long iterationStart;
            warmUp(NUMBER_OF_TRIES / 10);

            for (int n = 0; n < NUMBER_OF_TRIES; n++) {
                signatureBuffer = ByteBuffer.wrap(addPrefix(signature));
                messageBuffer.position(0);
                signatureBuffer.position(0);

                iterationStart = System.nanoTime();
                verifier.verify(messageBuffer, signatureBuffer);
                durations[n] = (System.nanoTime() - iterationStart);
            }

            long actualDuration = getMedian(durations);

            avgByteDurations[byteIndex] += actualDuration;

            if(actualDuration > maxDuration) {
                maxDuration = actualDuration;
                maxDurationValue = signature[byteIndex];
            }

            System.out.printf("Byte %d - try %d - input (%d) - duration %d .\n", byteIndex, findByteTries[byteIndex], (int) signature[byteIndex], actualDuration);
        }

        avgByteDurations[byteIndex] = Math.round(avgByteDurations[byteIndex] / 256d);
        signature[byteIndex] = maxDurationValue;
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
