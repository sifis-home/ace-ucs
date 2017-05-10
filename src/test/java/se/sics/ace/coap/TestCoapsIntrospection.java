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
package se.sics.ace.coap;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;

import org.junit.AfterClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import COSE.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;
import se.sics.ace.coap.rs.CoapsIntrospection;

/**
 * Test for the CoapsIntrospection class. 
 * 
 * NOTE: You need to run a fresh instance of TestCoAPServer to run this test!
 * 
 * @author Ludwig Seitz
 *
 */
public class TestCoapsIntrospection {
   
   static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
   static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
   
   /**
    * Deletes the test DB after the tests
    * 
    * @throws SQLException 
    * @throws AceException 
    * @throws IOException 
    */
   @AfterClass
   public static void tearDown() throws SQLException, AceException, IOException {
       String dbPwd = null;
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
       Properties connectionProps = new Properties();
       connectionProps.put("user", "root");
       connectionProps.put("password", dbPwd);
       Connection rootConn = DriverManager.getConnection(
               "jdbc:mysql://localhost:3306", connectionProps);

       String dropDB = "DROP DATABASE IF EXISTS " + DBConnector.dbName + ";";
       String dropUser = "DROP USER 'aceUser'@'localhost';";
       Statement stmt = rootConn.createStatement();
       stmt.execute(dropDB);
       stmt.execute(dropUser);    
       stmt.close();
       rootConn.close();   
   }
   
   /**
    * Test CoapIntrospect using RPK
    * 
    * @throws Exception
    */
   @Test
   public void testCoapIntrospect() throws Exception {
       OneKey key = new OneKey(
               CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));
       CoapsIntrospection i = new CoapsIntrospection(key, "coaps://localhost/introspect");
       Map<String, CBORObject> map =  i.getParams("token1");     
       System.out.println(map);
       assert(map.containsKey("aud"));
       assert(map.get("aud").AsString().equals("actuators"));
       assert(map.containsKey("scope"));
       assert(map.get("scope").AsString().equals("co2"));
       assert(map.containsKey("active"));
       assert(map.get("active").isTrue());
       assert(map.containsKey("cti"));
       assert(map.containsKey("exp"));
       
   }
}
