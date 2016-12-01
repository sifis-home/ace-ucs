package se.sics.ace.as;

import java.security.Principal;

/**
 * A principal implementation for testing purposes only.
 * 
 * @author Ludwig Seitz
 *
 */
public class Principal4Tests implements Principal {

    /**
     * The principal's name
     */
    private String name;
   
    /**
     * Constructor
     * 
     * @param name  the principal's name
     */
    public Principal4Tests(String name) {
        this.name = name;
    }
    
    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String toString() {
        return this.name;
    }
}
