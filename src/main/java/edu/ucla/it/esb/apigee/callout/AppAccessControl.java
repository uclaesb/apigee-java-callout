package edu.ucla.it.esb.apigee.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

/**
 * AppAccessControl
 */
public class AppAccessControl implements Execution {

    @Override
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            String reqUri = messageContext.getVariable("request.uri");
            String reqMethod = messageContext.getVariable("request.verb");
            String[] uriWithMethod = new String[]{};
            String accessControlList = messageContext.getVariable("app.auth.uris");
            boolean isAuthorizedRequest = false;
            if(accessControlList != null && accessControlList != ""){
                for(String accessControl:accessControlList.split("\\|")){
                    uriWithMethod = accessControl.split("(?=\\()");
                    isAuthorizedRequest = checkUriVerbLevelPermissions(reqUri, reqMethod, uriWithMethod, messageContext);
                    if(isAuthorizedRequest){
                        messageContext.setVariable("endpointContext", accessControl);
                        break;
                    }
                }
            }
            if(!isAuthorizedRequest){
                messageContext.setVariable("req.error.code", "403-Unauthorized");
                messageContext.setVariable("req.raise.fault", "true");
                messageContext.setVariable("req.status.code", "403");
            }

        } catch (Exception e) {
            return ExecutionResult.ABORT;
        }
		return ExecutionResult.SUCCESS;
	}
    private boolean checkUriVerbLevelPermissions(String reqUri, String reqMethod, String[] uriWithMethod, MessageContext messageContext) {
        if(uriWithMethod.length<2){
            return false;
        }else{
            if(reqUri.matches(uriWithMethod[1])){
                if(reqMethod.equalsIgnoreCase(uriWithMethod[0]) || reqMethod.matches("."+uriWithMethod[0])){
                    return true;
                }else{
                    return false;
                }
            }
            return false;
        }
    }
}