package md.bitcoin4j.generator;

import md.bitcoin4j.generator.model.PrivateAddress;
import org.twostack.bitcoin4j.params.NetworkType;

public interface AddressGenerator {
    PrivateAddress generate(NetworkType networkType) throws Exception;
}
