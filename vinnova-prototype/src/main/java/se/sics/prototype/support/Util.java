package se.sics.prototype.support;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.GroupOSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.Constants;
import se.sics.ace.oscore.GroupOSCORESecurityContextObject;
import se.sics.ace.oscore.GroupOSCORESecurityContextObjectParameters;
import se.sics.ace.oscore.OSCORESecurityContextObjectParameters;

/**
 * Class to hold various utility methods.
 * 
 *
 */
public class Util {
	/**
     * Compute a signature, using the same algorithm and private key used in the OSCORE group to join
     * 
     * @param privKey  private key used to sign
     * @param dataToSign  content to sign

     */
    public static byte[] computeSignature(PrivateKey privKey, byte[] dataToSign, int countersignKeyCurve) {

        Signature mySignature = null;
        byte[] clientSignature = null;

        try {
            if (countersignKeyCurve == KeyKeys.EC2_P256.AsInt32())
                mySignature = Signature.getInstance("SHA256withECDSA");
            else if (countersignKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
                mySignature = Signature.getInstance("NonewithEdDSA", "EdDSA");
            else {
                // At the moment, only ECDSA (EC2_P256) and EDDSA (Ed25519) are supported
                Assert.fail("Unsupported signature algorithm");
            }

        }
        catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            Assert.fail("Unsupported signature algorithm");
        }
        catch (NoSuchProviderException e) {
            System.out.println(e.getMessage());
            Assert.fail("Unsopported security provider for signature computing");
        }

        try {
            if (mySignature != null)
                mySignature.initSign(privKey);
            else
                Assert.fail("Signature algorithm has not been initialized");
        }
        catch (InvalidKeyException e) {
            System.out.println(e.getMessage());
            Assert.fail("Invalid key excpetion - Invalid private key");
        }

        try {
            if (mySignature != null) {
                mySignature.update(dataToSign);
                clientSignature = mySignature.sign();
            }
        } catch (SignatureException e) {
            System.out.println(e.getMessage());
            Assert.fail("Failed signature computation");
        }

        return clientSignature;

    }
    
    /**
     * Parse a received Group OSCORE join response and print the information in it.
     * 
     * @param joinResponse the join response
     */
    public static void printJoinResponse(CBORObject joinResponse) {
        
        //Parse the join response generally

        System.out.println();
        System.out.println("Join response contents: ");

        System.out.print("KTY: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.KTY)));

        System.out.print("KEY: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.KEY)));

        System.out.print("PROFILE: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PROFILE)));

        System.out.print("EXP: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.EXP)));

        System.out.print("PUB_KEYS: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)));

        System.out.print("NUM: ");
        System.out.println(joinResponse.get(CBORObject.FromObject(Constants.NUM)));

        //Parse the KEY parameter

        CBORObject keyMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
        
        System.out.println();
        System.out.println("KEY map contents: ");

        System.out.print("ms: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.ms)));

        System.out.print("clientId: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.clientId)));

        System.out.print("serverId: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.serverId)));

        System.out.print("hkdf: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.hkdf)));

        System.out.print("alg: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.alg)));

        System.out.print("salt: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.salt)));

        System.out.print("contextId: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.contextId)));

        System.out.print("rpl: ");
        System.out.println(keyMap.get(CBORObject.FromObject(OSCORESecurityContextObjectParameters.rpl)));


        System.out.print("cs_alg: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_alg)));

        System.out.print("cs_params: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_params)));

        System.out.print("cs_key_params: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_params)));

        System.out.print("cs_key_enc: ");
        System.out.println(keyMap.get(CBORObject.FromObject(GroupOSCORESecurityContextObjectParameters.cs_key_enc)));

        //Parse the PUB_KEYS parameter

        System.out.println();
        System.out.println("PUB_KEYS contents: ");

        byte[] coseKeySetByte = joinResponse.get(CBORObject.FromObject(Constants.PUB_KEYS)).GetByteString();
        CBORObject coseKeySetArray = CBORObject.DecodeFromBytes(coseKeySetByte);

        for(int i = 0 ; i < coseKeySetArray.size() ; i++) {

            CBORObject key_param = coseKeySetArray.get(i);

            System.out.println("Key " + i + ": " + key_param.toString());
        }
    }

    /**
     * Generate a Group OSCORE Security context from material
     * received in a Join response.
     * 
     * @param contextObject holds the information in the Join response
     * @param CBORObject coseKeySetArray holds information about public keys from the Join response
     * @param groupKeyPair the public and private COSE key of the client (in base64 encoding) 
     * 
     * @throws CoseException 
     */
    public static GroupOSCoreCtx generateGroupOSCOREContext(GroupOSCORESecurityContextObject contextObject, CBORObject coseKeySetArray, String groupKeyPair) throws CoseException {
        //Defining variables to hold the information before derivation

        //Algorithm
        AlgorithmID algo = null;
        CBORObject alg_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.alg);
        if(alg_param.getType() == CBORType.TextString) {
            algo = AlgorithmID.valueOf(alg_param.AsString());
        } else if(alg_param.getType() == CBORType.Number) {
            algo = AlgorithmID.FromCBOR(alg_param);
        }

        //KDF
        AlgorithmID kdf = null;
        CBORObject kdf_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.hkdf);
        if(kdf_param.getType() == CBORType.TextString) {
            kdf = AlgorithmID.valueOf(kdf_param.AsString());
        } else if(kdf_param.getType() == CBORType.Number) {
            kdf = AlgorithmID.FromCBOR(kdf_param);
        }

        //Algorithm for the countersignature
        AlgorithmID alg_countersign = null;
        CBORObject alg_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_alg);
        if(alg_countersign_param.getType() == CBORType.TextString) {
            alg_countersign = AlgorithmID.valueOf(alg_countersign_param.AsString());
        } else if(alg_countersign_param.getType() == CBORType.Number) {
            alg_countersign = AlgorithmID.FromCBOR(alg_countersign_param);
        }

        //Parameter for the countersignature
        Integer par_countersign = null;
        CBORObject par_countersign_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.cs_params);
        if(par_countersign_param.getType() == CBORType.Map) {
            par_countersign = par_countersign_param.get(KeyKeys.OKP_Curve.AsCBOR()).AsInt32();
            //TODO: Change like this in other places too?
        } else {
            System.err.println("Unknown par_countersign value!");
        }

        //Master secret
        CBORObject master_secret_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.ms);
        byte[] master_secret = null;
        if(master_secret_param.getType() == CBORType.ByteString) {
            master_secret = master_secret_param.GetByteString();
        }

        //Master salt
        CBORObject master_salt_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.salt);
        byte[] master_salt = null;
        if(master_salt_param.getType() == CBORType.ByteString) {
            master_salt = master_salt_param.GetByteString();
        }

        //Sender ID
        byte[] sid = null;
        CBORObject sid_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.clientId);
        if(sid_param.getType() == CBORType.ByteString) {
            sid = sid_param.GetByteString();
        }

        //Group ID / Context ID
        CBORObject group_identifier_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.contextId);
        byte[] group_identifier = null;
        if(group_identifier_param.getType() == CBORType.ByteString) {
            group_identifier = group_identifier_param.GetByteString();
        }

        //RPL (replay window information)
        CBORObject rpl_param = contextObject.getParam(GroupOSCORESecurityContextObjectParameters.rpl);
        int rpl = 32; //Default value
        if(rpl_param != null && rpl_param.getType() == CBORType.Number) {
            rpl = rpl_param.AsInt32();
        }

        //Set up private & public keys for sender (not from response but set by client)
        String sid_private_key_string = groupKeyPair;
        OneKey sid_private_key;
        sid_private_key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(sid_private_key_string)));

        //Now derive the actual context

        GroupOSCoreCtx groupOscoreCtx = null;
        try {
            groupOscoreCtx = new GroupOSCoreCtx(master_secret, true, algo, sid, kdf, rpl, 
                    master_salt, group_identifier, alg_countersign, par_countersign, sid_private_key);
        } catch (OSException e) {
            System.err.println("Failed to derive Group OSCORE Context!");
            e.printStackTrace();
        }

        Assert.assertNotNull(groupOscoreCtx);

        //Finally add the recipient contexts from the coseKeySetArray
        for(int i = 0 ; i < coseKeySetArray.size() ; i++) {

            CBORObject key_param = coseKeySetArray.get(i);

            byte[] rid = null;
            CBORObject rid_param = key_param.get(KeyKeys.KeyId.AsCBOR());
            if(rid_param.getType() == CBORType.ByteString) {
                rid = rid_param.GetByteString();
            }

            OneKey recipient_key = new OneKey(key_param);

            groupOscoreCtx.addRecipientContext(rid, recipient_key);
        }
        //Assert.assertEquals(groupOscoreCtx.getRecipientContexts().size(), 2);
        //System.out.println("Generated Group OSCORE Context:");
        //Utility.printContextInfo(groupOscoreCtx);

        return groupOscoreCtx;
    }
}
