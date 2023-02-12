package org.twostack.bitcoin4j.utils;

import java.math.BigInteger;
import java.util.Arrays;

public class BigIntegers {
    private BigIntegers() {}

    public static byte[] toNonLeadingZeroArray(BigInteger value) {
        byte[] signedValue = value.toByteArray();

        if (signedValue[0] != 0) return signedValue;

        return Arrays.copyOfRange(signedValue, 1, signedValue.length);
    }
}
