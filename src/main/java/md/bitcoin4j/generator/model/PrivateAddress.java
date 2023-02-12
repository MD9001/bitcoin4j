package md.bitcoin4j.generator.model;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PrivateKey;

public final class PrivateAddress {
    private final Address publicAddress;
    private final PrivateKey privateKey;

    public PrivateAddress(Address publicAddress, PrivateKey key) {
        this.publicAddress = publicAddress;
        this.privateKey = key;
    }

    public Address getPublicAddress() {
        return publicAddress;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
