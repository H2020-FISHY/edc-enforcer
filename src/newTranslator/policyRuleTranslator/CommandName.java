package policyRuleTranslator;

import java.util.HashMap;

public class CommandName {
    String commandName; 
    HashMap<String,String> commandNameCondition; 


    public CommandName(String commandName, HashMap<String,String> commandNameCondition) {
        this.commandName = commandName;
        this.commandNameCondition = commandNameCondition;
    }

    
}
