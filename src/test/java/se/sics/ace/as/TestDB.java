package se.sics.ace.as;

import java.sql.ResultSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.MessageTag;
import junit.framework.Assert;
import se.sics.ace.COSEparams;

/**
 * Test the database connection classes.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestDB {
  
    static CBORObject cnKeyPublic;
    static CBORObject cnKeyPublicCompressed;
    static ECPublicKeyParameters keyPublic;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    /**
     * Set up tests.
     */
    @BeforeClass
    public static void setUpClass() {
        
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        
        ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, null);
        pGen.init(genParam);
        
        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();
        
        keyPublic = (ECPublicKeyParameters) p1.getPublic();
        
        byte[] rgbX = keyPublic.getQ().normalize().getXCoord().getEncoded();
        byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();

        cnKeyPublic = CBORObject.NewMap();
        cnKeyPublic.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        cnKeyPublic.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        cnKeyPublic.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        cnKeyPublic.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        
        cnKeyPublicCompressed = CBORObject.NewMap();
        cnKeyPublicCompressed.Add(KeyKeys.KeyType.AsCBOR(), 
                    KeyKeys.KeyType_EC2);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_Curve.AsCBOR(), 
                    KeyKeys.EC2_P256);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
        cnKeyPublicCompressed.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
        
    }
     
    /**
     * Test the database functions exposed by <code>DBConnector</code>
     * 
     * XXX: The database admin password is hardcoded here for now
     * 
     * @throws Exception 
     */
    @Test
    public void testDB() throws Exception {
        SQLConnector db = new SQLConnector(null, null, null);
        db.init("ZzIbt3ELL34vEJITzaAIxT");
        
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        profiles.add("coap_oscoap");
        
        Set<String> scopes = new HashSet<>();
        scopes.add("temp");
        scopes.add("co2");
        
        Set<String> auds = new HashSet<>();
        auds.add("sensors");
        auds.add("actuators");
        
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        
        Set<Integer> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        
        COSEparams cose = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        
        long expiration = 1000000L;
       
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, 
                expiration, key128, cnKeyPublicCompressed);
        
        profiles.remove("coap_oscoap");
        scopes.clear();
        auds.remove("actuators");
        keyTypes.remove("PSK");
        tokenTypes.remove(AccessTokenFactory.REF_TYPE);
        expiration = 300000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, key128, null);
        
        profiles.clear();
        profiles.add("coap_oscoap");
        scopes.add("co2");
        auds.clear();
        auds.add("actuators");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        expiration = 30000L;
        db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, cnKeyPublicCompressed);
        
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient("clientA", profiles, null, null, keyTypes, null, cnKeyPublicCompressed);
  
        profiles.clear();
        profiles.add("coap_oscoap");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientB", profiles, "co2", "sensors", keyTypes, key128, null);
        
        ResultSet result = db.getProfiles("sensors", "clientA");
        Set<String> expectedResults = new HashSet<>();
        expectedResults.add("rs1:coap_dtls");
        expectedResults.add("rs1:coap_oscoap");
        expectedResults.add("rs2:coap_dtls");
        expectedResults.add("clientA:coap_dtls");
        while (result.next()) {
            String id = result.getString(DBConnector.idColumn);
            String profile = result.getString(DBConnector.profileColumn);
            String r = id + ":" + profile;
            expectedResults.remove(r);            
        }  
        result.close();
        assert(expectedResults.isEmpty());
    }
    
//    
//     *public ResultSet getProfiles(String audience, String clientId) 
//                throws SQLException;
//    
//    /**
//     * Gets the key types supported by a specific audience and client
//     * 
//     * @param audience  the audience identifier
//     * @param clientId  the client identifier
//     * @return  the key types they all support
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getkeyTypes(String audience, String clientId) 
//                throws SQLException;
//    
//    /**
//     * Gets the scopes supported by a specific audience
//     * 
//     * @param audience  the audience identifier
//     *
//     * @return  the scopes they all support
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getScopes(String audience) 
//                throws SQLException;
//    
//    /**
//     * Gets the token types (CWT or Reference) supported by a specific audience
//     * 
//     * @param audience  the audience identifier
//     *
//     * @return  the token types they all support
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getTokenType(String audience) 
//                throws SQLException;
//    
//    /**
//     * Gets the Cose encoding for CWTs all members of an audience support
//     * 
//     * @param audience  the audience identifier
//     *
//     * @return  the Cose encoding they all support
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getCose(String audience) 
//                throws SQLException; 
//    
//    /**
//     * Gets the RSs that are part of this audience.
//     * 
//     * @param audience  the audience identifier
//     *
//     * @return  the RS identifiers of those that are part of this audience
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getRSS(String audience) 
//                throws SQLException; 
//    
//    
//    /**
//     * Gets the audiences that this RS is part of.
//     * 
//     * @param rs  the rs identifier
//     *
//     * @return  the audience identifiers that this RS is part of
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getAudiences(String rs) 
//                throws SQLException; 
//    
//    /**
//     * Get the default expiration time of access tokens for an RS.
//     *  
//     * @param rs  the rs identifier
//     * 
//     * @return  the expiration time
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getExpTime(String rs)
//        throws SQLException;
//    
//    /**
//     * Get the shared symmetric key (PSK) with this RS
//     *  
//     * @param rs  the rs identifier
//     * 
//     * @return  the shared symmetric key if there is any
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getRsPSK(String rs)
//        throws SQLException;
//    
//    /**
//     * Get the public key (RPK) of this RS
//     *  
//     * @param rs  the rs identifier
//     * 
//     * @return  the public key if there is any
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getRsRPK(String rs)
//        throws SQLException;
//    
//    /**
//     * Get the shared symmetric key (PSK) with this client
//     *  
//     * @param client  the client identifier
//     * 
//     * @return  the shared symmetric key if there is any
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getCPSK(String client)
//        throws SQLException;
//    
//    /**
//     * Get the public key (RPK) of this client
//     *  
//     * @param client  the client identifier
//     * 
//     * @return  the public key if there is any
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getCRPK(String client)
//        throws SQLException;
//    
//    /**
//     * Get the default scope of this client
//     *  
//     * @param client  the client identifier
//     * 
//     * @return  the default scope used by this client if any
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getDefaultScope(String client)
//        throws SQLException;
//    
//    /**
//     * Get the default audience of this client
//     *  
//     * @param client  the client identifier
//     * 
//     * @return  the default audience used by this client if any
//     * 
//     * @throws SQLException 
//     */
//    public ResultSet getDefaultAudience(String client)
//        throws SQLException;

//    /**
//     * Deletes an RS and all related registration data.
//     * 
//     * @param rs  the identifier of the RS
//     * 
//     * @throws SQLException
//     */
//    public void deleteRS(String rs) 
//            throws SQLException;
//    
//
//    
//    /**
//     * Deletes a client and all related data
//     * 
//     * @param client  the identifier for the client
//     * 
//     * @throws SQLException 
//     */
//    public void deleteClient(String client) throws SQLException;
//
//    
//    /**
//     * Adds a new token to the database
//     * @param cid  the token identifier
//     * @param token  the token raw content
//     * @param claims  the claims of this token
//     * 
//     * @throws SQLException 
//     */
//    public void addToken(String cid, AccessToken token, 
//            Map<String, CBORObject> claims) throws SQLException;
//    
//    /**
//     * Deletes an existing token from the database
//     * @param cid  the token identifier
//     * 
//     * @throws SQLException 
//     */
//    public void deleteToken(String cid) throws SQLException;
//    
//    /**
//     * Selects an existing token from the database
//     * @param cid  the token identifier
//     * 
//     * @return  the raw token data
//     * 
//     * @throws SQLException
//     */
//    public ResultSet getToken(String cid) throws SQLException;
//    
//    
//    /**
//     * Deletes all expired tokens from the database
//     * 
//     * @param now  the current time
//     * 
//     * @throws SQLException 
//     */
//    public void purgeExpiredTokens(long now) throws SQLException;
//    
//    
//    /**
//     * Returns the claims associated with this token.
//     * 
//     * @param cid  the token identifier
//     * 
//     * @return  the set of claims
//     *  
//     * @throws SQLException
//     */
//    public ResultSet getClaims(String cid) throws SQLException;
//    
//    /**
//     * Close the connections. After this any other method calls to this
//     * object will lead to an exception.
//     * 
//     * @throws SQLException
//     */
//    public void close() throws SQLException;
///
//    
}
