package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.script.Script;
import org.twostack.bitcoin.script.ScriptBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

abstract class UnlockingScriptBuilder {

    List<TransactionSignature> signatures = new ArrayList<>();

    protected Script script;

    UnlockingScriptBuilder(Script script){
        this.script = script;
    }

    UnlockingScriptBuilder(){
        this.script = new ScriptBuilder().build();
    }

    public abstract Script getScriptSig();

    public List<TransactionSignature> getSignatures() {
        return Collections.unmodifiableList(signatures);
    }

    public void addSignature(TransactionSignature signature) {
        this.signatures.add(signature);
    }

}
