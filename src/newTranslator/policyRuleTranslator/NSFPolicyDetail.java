package policyRuleTranslator;

import java.util.HashMap;
import java.util.List;

public class NSFPolicyDetail {
    String ruleStart; 
    String ruleEnd; 
    String policyTrailer; 
    String policyEncoding; 
    String resolutionStrategyInfo; 
    String defaultSecurityCapability;
    String capabilityStart;
    List<String> requiredPolicyAttributes; 
    List<String> requiredRuleAttributes; 
    List<String> supportedDefaultActions; 
    HashMap<String, HashMap<String,String>> ruleAttributeDetails; 



    public NSFPolicyDetail() {
    }
    


    public NSFPolicyDetail(String ruleStart, String ruleEnd, String policyTrailer, String policyEncoding, String resolutionStrategyInfo, String defaultSecurityCapability, List<String> requiredPolicyAttributes, List<String> requiredRuleAttributes, List<String> supportedDefaultActions, HashMap<String, HashMap<String,String>> ruleAttributeDetails, String capabilityStart) {
        this.ruleStart = ruleStart;
        this.ruleEnd = ruleEnd;
        this.policyTrailer = policyTrailer;
        this.policyEncoding = policyEncoding;
        this.resolutionStrategyInfo = resolutionStrategyInfo;
        this.defaultSecurityCapability = defaultSecurityCapability;
        this.requiredPolicyAttributes = requiredPolicyAttributes;
        this.requiredRuleAttributes = requiredRuleAttributes;
        this.supportedDefaultActions = supportedDefaultActions;
        this.ruleAttributeDetails = ruleAttributeDetails;
        this.capabilityStart = capabilityStart; 
    }
    
    
   

    
}
