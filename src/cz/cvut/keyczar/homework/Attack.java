package cz.cvut.keyczar.homework;

import cz.cvut.keyczar.Verifier;
import cz.cvut.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Random;

/**
 * Own implementation of timing attack.
 *
 * !Implemented and tested on Windows! Behaviour on other platform is not know.
 *
 * The signature is guessed byte by byte. If it seems that wrong value was taken (the verification time does not
 * increase) then the it is re-guessed.
 *
 * @author moravja8
 */
public class Attack {

    private static final byte[] GOOD_PREAMBLE = {0, 92, 17, -97, -123};

    private static final int SIGNATURE_LENGTH = 20;
    private static final int PREAMBLE_LENGTH = 5;

    private static final int NUMBER_OF_TRIES = 50;

    private static final String DIFFICULTY = "";

    private static Verifier verifier;
    private static byte[] message;
    private static long[] avgByteDurations;
    private static byte[] signature;
    private static int[] findByteTries;
    private static Byte[] possibleInputs;

    public static void main(String[] args) throws KeyczarException {

        verifier = new Verifier("./keys");
        message = "Hello world".getBytes();

        System.setProperty("difficulty", DIFFICULTY);

        warmUp(250000);

        avgByteDurations = new long[SIGNATURE_LENGTH];
        signature = new byte[SIGNATURE_LENGTH];
        findByteTries = new int[SIGNATURE_LENGTH];
        Arrays.fill(signature, Byte.MIN_VALUE);

        // generate possible
        possibleInputs = new Byte[256];
        for (int i = 0; i < 256; i++) {
            possibleInputs[i] = byteIndexToValue(i);
        }

        for (int i = 0; i < SIGNATURE_LENGTH; i++) {
            findByte(i);

            // fallback if we made bad guess
            // iff avg result time too low then redo last iteration
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
     * Tries to find a correct value for the byte with given index.
     *
     * All possibilities are tested n-times. In each iteration, possibilities are shuffled
     * so that the impact of runtime optimization is eliminated. From results of n iterations
     * for each possible value is taken median, which is the comparison value.
     *
     * After all this happens, the the value which caused slowest verification is taken as the correct one.
     *
     * The correct byte is seted to signature.
     *
     * @param byteIndex index of byte that should be guessed
     * @throws KeyczarException something went terribly wrong
     */
    private static void findByte(int byteIndex) throws KeyczarException {
        byte maxDurationValue = 0;
        long maxDuration = Integer.MIN_VALUE;
        ByteBuffer messageBuffer = ByteBuffer.wrap(message);
        ByteBuffer signatureBuffer;
        avgByteDurations[byteIndex] = 0;
        findByteTries[byteIndex]++;

        warmUp(NUMBER_OF_TRIES);

        long[][] durations = new long[possibleInputs.length][NUMBER_OF_TRIES];
        for (int n = 0; n < NUMBER_OF_TRIES; n++) {
            LinkedList<Byte> candidates = new LinkedList<>();
            candidates.addAll(Arrays.asList(possibleInputs));
            Collections.shuffle(candidates); // shuffle is done to minimize JVM optimizations (and/or other performance tuning during iteration)

            Byte candidate;
            while ((candidate = candidates.pollFirst()) != null) {
                signature[byteIndex] = candidate;
                signatureBuffer = ByteBuffer.wrap(addPrefix(signature));
                messageBuffer.position(0);
                signatureBuffer.position(0);

                long iterationStart = System.nanoTime();
                verifier.verify(messageBuffer, signatureBuffer);
                long iterationEnd = System.nanoTime();

                durations[byteValueToIndex(candidate)][n] = (iterationEnd - iterationStart);
            }
        }

        for (int i = 0; i < possibleInputs.length; i++) {
            long actualDuration = getMedian(durations[i]);

            avgByteDurations[byteIndex] += actualDuration;

            if(actualDuration > maxDuration) {
                maxDuration = actualDuration;
                maxDurationValue = byteIndexToValue(i);
            }

            System.out.printf("Byte %d - try %d - input (%d) - duration %d .\n", byteIndex, findByteTries[byteIndex], byteIndexToValue(i), actualDuration);
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

    /**
     * Java byte values are -127 to 126, but we want to stare them in simple array.
     * This metod transfers array index to value.
     * @param byteIndex array index
     * @return byte value
     */
    private static byte byteIndexToValue(int byteIndex) {
        return (byte) (byteIndex - ((int) Byte.MIN_VALUE * -1));
    }

    /**
     * Java byte values are -127 to 126, but we want to stare them in simple array.
     * This metod transfers value to array index.
     * @param byteValue byteValue
     * @return array index
     */
    private static int byteValueToIndex(int byteValue) {
        return byteValue + ((int) Byte.MIN_VALUE * -1);
    }
}
