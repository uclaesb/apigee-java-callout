package edu.ucla.it.esb.apigee.callout;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Locale;
import java.util.TimeZone;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

/**
 * EsmAuditCallOut
 */
public class UclaExtractRequestLog implements Execution {

    @Override
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            String oauthToken = messageContext.getVariable("access_token");
            String clientAuthnScheme = "";
            String apiKeyIssueAt = messageContext.getVariable("verifyapikey.Verify-API-Key.issued_at");
            String xapikey = messageContext.getVariable("request.header.x-apikey");
            String clientCN = messageContext.getVariable("client.cn");
            String clientCredId = messageContext.getVariable("client_id");
            String clientAuthnSubject = messageContext.getVariable("developer.app.name");
            String responseMessage = messageContext.getVariable("req.error.message");
            if(oauthToken != null && !oauthToken.isEmpty()){
                clientAuthnScheme = "oauth2_client_cred";
                messageContext.setVariable("clientCredId", clientCredId);
            }else if((apiKeyIssueAt != null && !apiKeyIssueAt.isEmpty()) || 
            (xapikey != null && !xapikey.isEmpty())){
                clientAuthnScheme = "api_key";
                messageContext.setVariable("clientCredId", "");
            }else if(clientCN != null && !clientCN.isEmpty()){
                clientAuthnScheme = "tls_client_cert";
                messageContext.setVariable("clientCredId", clientCredId);
            }else if(clientAuthnSubject != null || responseMessage != null){
                clientAuthnScheme = "client_ip";
                messageContext.setVariable("clientCredId", clientCredId);
            }else{
                clientAuthnScheme = "no_auth";
            }
            messageContext.setVariable("clientAuthnScheme", clientAuthnScheme);
            return ExecutionResult.SUCCESS;
        } catch (Exception e) {
            return ExecutionResult.ABORT;
        }
	}

    
}