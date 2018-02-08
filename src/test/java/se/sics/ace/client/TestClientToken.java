/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.Introspect;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.rs.TokenRepository;

/**
 * Tests the client side of the client token code.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestClientToken {
    
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static SQLConnector db = null;
    
    private static String dbPwd = null;

    private static KissPDP pdp = null;
    private static Introspect i; 
    private static TokenRepository tr = null;
    
    /**
     * Set up tests.
     * @throws SQLException 
     * @throws AceException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() 
            throws SQLException, AceException, IOException, CoseException {
        
        BufferedReader br = new BufferedReader(new FileReader("db.pwd"));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            dbPwd = sb.toString().replace(
                    System.getProperty("line.separator"), "");     
        } finally {
            br.close();
        }
        
        //Just to be sure no old test pollutes the DB
        SQLConnector.wipeDatabase(dbPwd);
        
        SQLConnector.createUser(dbPwd, "aceuser", "password", 
                "jdbc:mysql://localhost:3306");
        SQLConnector.createDB(dbPwd, "aceuser", "password", null,
                "jdbc:mysql://localhost:3306");

     
        
        OneKey k_c_as = new OneKey();
        k_c_as.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        k_c_as.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x74, 0x11}));
        k_c_as.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
       
        OneKey k_cnf = new OneKey();
        k_cnf.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        k_cnf.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x11, 0x34}));
        k_cnf.add(KeyKeys.Octet_K, CBORObject.FromObject(key128a));
        
        db = SQLConnector.getInstance(null, null, null);
        
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        db.addClient("client", profiles, null, null, keyTypes, k_c_as, null);
       
        
        Set<String> actions = new HashSet<>();
        actions.add("GET");
        Map<String, Set<String>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<String>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
                
        KissValidator valid = new KissValidator(Collections.singleton("rs1"),
                myScopes);
        createTR(valid);
        tr = TokenRepository.getInstance();
        pdp = new KissPDP(dbPwd, db);
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess("rs1");
        
        i = new Introspect(pdp, db, new KissTime(), null);
        
        //Set up token for introspection
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x08}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("rs1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, k_cnf.AsCBOR());
        params.put(Constants.CNF, cbor);
        
        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x08}), params);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x08});
        db.addCti2Client(ctiStr, "client");

    }
   
    /**
     * Create the Token repository if not already created,
     * if already create ignore.
     * 
     * @param valid 
     * @throws IOException 
     * 
     */
    private static void createTR(KissValidator valid) throws IOException {
        try {
            TokenRepository.create(valid, TestConfig.testFilePath 
                    + "tokens.json", null);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath 
                        + "tokens.json", null);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            }
           
            
        }
    } 
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws SQLException 
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws SQLException, AceException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", "root");
        connectionProps.put("password", dbPwd);
        Connection rootConn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306", connectionProps);
              
        String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
        String dropUser = "DROP USER 'aceuser'@'localhost';";
        Statement stmt = rootConn.createStatement();
        stmt.execute(dropDB);
        stmt.execute(dropUser);        
        stmt.close();
        rootConn.close();
        db.close();
        i.close();
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
}
