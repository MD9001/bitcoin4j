package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.PublicKey;
import org.twostack.bitcoin.Utils;
import org.twostack.bitcoin.script.*;

import java.util.List;

public class P2PKHUnlockBuilder extends UnlockingScriptBuilder {

    PublicKey signerPubkey;

    P2PKHUnlockBuilder(Script script){
        parse(script);
    }

    P2PKHUnlockBuilder(PublicKey publicKey) {
        this.signerPubkey = publicKey;
    }

    private void parse(Script script){

        if (script != null) {

            List<ScriptChunk> chunkList = script.getChunks();

            if (chunkList.size() != 2){
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Wrong number of data elements for P2PKH ScriptSig");
            }

            byte[] sig = chunkList.get(0).data;
            byte[] pubKey = chunkList.get(1).data;

            signerPubkey = PublicKey.fromHex(Utils.HEX.encode(pubKey));
            signatures.add(TransactionSignature.fromTxFormat(Utils.HEX.encode(sig)));

        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Invalid Script or Malformed Script.");
        }
    }

    @Override
    public Script getScriptSig() {

        TransactionSignature signature = getSignatures().get(0);

        if (signature == null || signerPubkey == null){
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Missing signature or public key. scriptSig won't be created.");
        }

        return new ScriptBuilder().data(signature.signatureBytes).data(signerPubkey.getPubKeyBytes()).build();
    }
}
