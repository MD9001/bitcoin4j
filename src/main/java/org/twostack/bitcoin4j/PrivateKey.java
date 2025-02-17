
/*
 * Copyright 2021 Stephan M. February
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.twostack.bitcoin4j;

import org.twostack.bitcoin4j.address.Base58;
import org.twostack.bitcoin4j.exception.InvalidKeyException;
import org.twostack.bitcoin4j.params.NetworkType;
import org.twostack.bitcoin4j.transaction.ReadUtils;

import java.math.BigInteger;

public class PrivateKey {

    ECKey key;
    boolean _hasCompressedPubKey;
    NetworkType _networkType;

    public PrivateKey() {
        this(new ECKey(), true, NetworkType.MAIN);
    }

    public PrivateKey(ECKey key) {
        this(key, true, NetworkType.MAIN);
    }

    public PrivateKey(ECKey key, boolean isCompressed, NetworkType networkType) {
        this.key = key;
        this._hasCompressedPubKey = isCompressed;
        this._networkType = networkType;
    }

    //FIXME: We can use DumpedPrivateKey to replace the internals here
    public static PrivateKey fromWIF(String wif) throws InvalidKeyException {

        boolean isCompressed = false;

        if (wif.length() != 51 && wif.length() != 52) {
            throw new InvalidKeyException("Valid keys are either 51 or 52 bytes in length");
        }

        //decode from base58
        byte[] versionAndDataBytes = Base58.decodeChecked(wif);

        NetworkType networkType = decodeNetworkType(wif);

        //strip first byte
        ReadUtils reader = new ReadUtils(versionAndDataBytes);
        byte version = reader.readByte();
        byte[] dataBytes = reader.readBytes(versionAndDataBytes.length - 1);

        byte[] keyBytes = dataBytes.clone();
        if (dataBytes.length == 33) {
            //drop last byte
            //throw error if last byte is not 0x01 to indicate compression
            if (dataBytes[32] != 0x01) {
                throw new InvalidKeyException("Compressed keys must have last byte set as 0x01. Yours is [" + dataBytes[32] + "]");
            }

            keyBytes = new ReadUtils(dataBytes).readBytes(32);
            isCompressed = true;
        }

        String keyHex = Utils.HEX.encode(keyBytes);
        BigInteger d = new BigInteger(keyHex, 16);

        ECKey key = ECKey.fromPrivate(d);

        return new PrivateKey(key, isCompressed, networkType);
    }

    private static NetworkType decodeNetworkType(String wifKey) throws InvalidKeyException {

        switch (wifKey.charAt(0)) {
            case '5': {
                if (wifKey.length() != 51) {
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");
                }

                return NetworkType.MAIN;
            }
            case '9': {
                if (wifKey.length() != 51) {
                    throw new InvalidKeyException("Uncompressed private keys have a length of 51 bytes");
                }

                return NetworkType.TEST;
            }
            case 'L':
            case 'K': {
                if (wifKey.length() != 52) {
                    throw new InvalidKeyException("Compressed private keys have a length of 52 bytes");
                }

                return NetworkType.MAIN;
            }
            case 'c': {
                if (wifKey.length() != 52) {
                    throw new InvalidKeyException("Compressed private keys have a length of 52 bytes");
                }

                return NetworkType.TEST;
            }
            default: {
                throw new InvalidKeyException("Address WIF format must start with either [5] , [9], [L], [K] or [c]");
            }

        }
    }

    public byte[] sign(byte[] buffer) {
        ECKey.ECDSASignature sig = this.key.sign(Sha256Hash.wrap(buffer));
        return sig.encodeToDER();
    }

    public String toWIF() {
        return key.getPrivateKeyAsWiF(_networkType);
    }

    public String toWif(NetworkType networkType) {
        return this.key.getPrivateKeyAsWiF(networkType);
    }

    /**
     * @return the PublicKey corresponding to this PrivateKey
     */
    public PublicKey getPublicKey() {
        return PublicKey.fromHex(Utils.HEX.encode(key.getPubKey()));
    }


    /**
     * @return the ECKey backing this private key.
     */
    public ECKey getKey() {
        return this.key;
    }
}
