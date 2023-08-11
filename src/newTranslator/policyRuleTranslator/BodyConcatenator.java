package policyRuleTranslator;

import java.util.ArrayList;

public class BodyConcatenator {
    String realConcatenator = ""; 
    String preVariable;
    String postVariable; 
    String postConcatenator; 
    String operatorType;
    String supportPolicyAttribute;
    String concatSuppPolWithCapaValue; 
    ArrayList<CommandName> commandNames; 

    public BodyConcatenator() {
    }


    public BodyConcatenator(String realConcatenator, String preVariable, String postVariable, String postConcatenator, String operatorType, String supportPolicyAttribute, String concatSuppPolWithCapaValue, ArrayList<CommandName> commandNames) {
        this.realConcatenator = realConcatenator;
        this.preVariable = preVariable;
        this.postVariable = postVariable;
        this.postConcatenator = postConcatenator;
        this.operatorType = operatorType;
        this.supportPolicyAttribute = supportPolicyAttribute;
        this.concatSuppPolWithCapaValue = concatSuppPolWithCapaValue;
        this.commandNames = commandNames;
    }

    public BodyConcatenator(BodyConcatenator copy) {
        this.realConcatenator = copy.realConcatenator;
        this.preVariable = copy.preVariable;
        this.postVariable = copy.postVariable;
        this.postConcatenator = copy.postConcatenator;
        this.operatorType = copy.operatorType;
        this.supportPolicyAttribute = copy.supportPolicyAttribute;
        this.concatSuppPolWithCapaValue = copy.concatSuppPolWithCapaValue;
        this.commandNames = copy.commandNames;
    }

    
}
