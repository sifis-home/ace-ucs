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
package se.sics.ace.coap.as;

import java.net.InetSocketAddress;
import java.sql.SQLException;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.KeyKeys;
import COSE.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.examples.SQLDBAdapter;

/**
 * A SQLConnector for CoAP, implementing the PskStore interface.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapDBConnector extends SQLConnector implements PskStore {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapDBConnector.class.getName() );
    
    /**
     * Constructor.
     *  
     * @param dbUrl  the database URL, if null the default will be used
     * @param user   the database user, if null the default will be used
     * @param pwd    the database user's password, if null the default 
     *               will be used
     *
     * @throws SQLException
     */
    public CoapDBConnector(String dbUrl, String user, String pwd)
            throws SQLException {
        super(dbUrl, user, pwd);

    }

    /**
     * Constructor.
     *
     * @param dbAdapter handler for engine-db specific commands.
     * @param dbUrl     the database URL, if null the default will be used
     * @param user      the database user, if null the default will be used
     * @param pwd       the database user's password, if null the default
     *                  will be used
     *
     * @throws SQLException
     */
    public CoapDBConnector(SQLDBAdapter dbAdapter, String dbUrl, String user, String pwd)
            throws SQLException {
        super(dbAdapter, dbUrl, user, pwd);
    }

    @Override
    public byte[] getKey(String identity) {
        OneKey key = null;
        try {
            key = super.getCPSK(identity);
        } catch (AceException e) {
            LOGGER.severe(e.getMessage());
            return null;
        }
        if (key == null) {
            try {
                key = super.getRsPSK(identity);
            } catch (AceException e) {
                LOGGER.severe(e.getMessage());
                return null;
            }
        }
        if (key == null) { //Key not found
           return null;
        }
        CBORObject val = key.get(KeyKeys.KeyType);
        if (val.equals(KeyKeys.KeyType_Octet)) {
            val = key.get(KeyKeys.Octet_K);
            if ((val== null) || (val.getType() != CBORType.ByteString)) {
                return null; //Malformed key
            }
            return val.GetByteString();
        }
        return null; //Wrong KeyType
          
        
    }

    @Override
    public String getIdentity(InetSocketAddress inetAddress) {
        return null;
    }

}
