package ConverterXMItoXSD;

import java.util.HashMap;

public class Enumeration {
    String enumerationName; 
    HashMap<String, String> enumerationLiterals; 


    public Enumeration(String enumerationName, HashMap<String,String> enumerationLiterals) {
        this.enumerationName = enumerationName;
        this.enumerationLiterals = enumerationLiterals;
    }

}
