import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
public class TxHandler {

    private UTXOPool pool;
    private double totalInputSum;
   
    public TxHandler(UTXOPool utxoPool) {
        this.pool = new UTXOPool(utxoPool);
        this.totalInputSum = 0;
    }

    public boolean isValidTx(Transaction tx) {
        this.totalInputSum = 0;
        return validateRuleNumber12And3(tx) &&
               validateRuleNumber4And5(tx);
    }

    private boolean validateRuleNumber12And3(Transaction tx) {
        HashMap<UTXO, Boolean> usedUTXO = new HashMap<UTXO, Boolean>();

        for (int i = 0;  i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            if (input == null) { return false; }

            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            //rule number 1
            if (this.pool.contains(utxo) == false) {
              return false;
            }

            Transaction.Output previousTxOutput = this.pool.getTxOutput(utxo);
            if (previousTxOutput == null) { return false; }

            PublicKey publicKey = previousTxOutput.address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = input.signature;
            //rule number 2
            if (Crypto.verifySignature(publicKey, message, signature) == false) {
              return false;
            }

            //rule number 3
            if (usedUTXO.containsKey(utxo)) { return false; }

            usedUTXO.put(utxo, true);

            //saving this value for rule number 5
            this.totalInputSum += previousTxOutput.value;
        }

        return true;
    }

    private boolean validateRuleNumber4And5(Transaction tx) {
        double outputSum = 0;

        for (int i = 0;  i < tx.numOutputs(); i++) {
            Transaction.Output output = tx.getOutput(i);
            if (output == null) { return false; }
            if (output.value < 0) { return false; }

            outputSum += output.value;
        }

        return this.totalInputSum >= outputSum;
    }

    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        if (possibleTxs == null) {
            return new Transaction[0];
        }

        ArrayList<Transaction> validTxs = new ArrayList<>();

        for (Transaction tx : possibleTxs) {
            if (!isValidTx(tx)) {
                continue;
            }
            validTxs.add(tx);

            for (Transaction.Input input : tx.getInputs()) {
                UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                this.pool.removeUTXO(utxo);
            }
            byte[] txHash = tx.getHash();
            int index = 0;
            for (Transaction.Output output : tx.getOutputs()) {
                UTXO utxo = new UTXO(txHash, index);
                index += 1;
                this.pool.addUTXO(utxo, output);
            }
        }

        return validTxs.toArray(new Transaction[validTxs.size()]);
    }

}
