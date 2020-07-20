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
public class EsmAuditCallOut implements Execution {
        private static final long SECOND = 1000L;
	    private static final long MINUTE = 60 * SECOND;
	    private static final long HOUR = 60 * MINUTE;
	    private static final long DAY = 24 * HOUR;
	    private static final long YEAR = 365 * DAY;

    @Override
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            byte[] decodedPem = null;
            String environment = messageContext.getVariable("environment.name");
            String clientCN = messageContext.getVariable("client.cn");
            String appDomain = "";
            SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS a zzz");
            ft.setTimeZone(TimeZone.getTimeZone("PST"));
            long reqTime = messageContext.getVariable("client.received.end.timestamp");
            String reqTS = ft.format(reqTime);
            String clientAuthnSubject = messageContext.getVariable("developer.app.name");
            String clientScheme = messageContext.getVariable("client.scheme");
            String vhAlias[] = messageContext.getVariable("virtualhost.aliases");
            String proxyBasePath = messageContext.getVariable("proxy.basepath");
            String proxyPathSuffix = messageContext.getVariable("proxy.pathsuffix");
            String requestUri = clientScheme + "://"+ vhAlias[0]+ proxyBasePath + proxyPathSuffix;
            String targetURL = messageContext.getVariable("target.url");
            String clientIp = messageContext.getVariable("proxy.client.ip");
            String ipContext = messageContext.getVariable("ip.context");
            String reqMethod = messageContext.getVariable("request.verb");
            String clientAuthnScheme = "";
            //cn/oauth2 client id or other
            String clientCredId = messageContext.getVariable("client_id");
            String xapikey = messageContext.getVariable("request.header.x-apikey");
            String endpointContext = messageContext.getVariable("endpointContext");
            String responseMessage = messageContext.getVariable("req.error.message");
            String apiproductName = messageContext.getVariable("apiproduct.name");
            String apiProxyName = messageContext.getVariable("apiproxy.name");
            String clientCredCreateTS = "";
            String clientCredExpireTS = "";
            String clientCredTTL = "";
            String apiKeyIssueAt = messageContext.getVariable("verifyapikey.Verify-API-Key.issued_at");
            String oauthTokenIssueAt = messageContext.getVariable("issued_at");
            String oauthTokenExpiresIn = messageContext.getVariable("expires_in");
            String httpResposeCode = messageContext.getVariable("req.status.code");
            Long spSentTime = messageContext.getVariable("target.sent.end.timestamp");
            String spReqTS = "";
            Long spReceivedTime = messageContext.getVariable("target.received.end.timestamp");
            String spRespTS = "";
            String spElapsedTime = "";
            String oauthToken = messageContext.getVariable("access_token");
            String appDomains = messageContext.getVariable("ucla.app.domains");
            if(oauthToken != null && !oauthToken.isEmpty()){
                clientAuthnScheme = "oauth2_client_cred";
                clientCredId = "";
            }else if((apiKeyIssueAt != null && !apiKeyIssueAt.isEmpty()) || 
            (xapikey != null && !xapikey.isEmpty())){
                clientAuthnScheme = "api_key";
                clientCredId = "";
            }else if(clientCN != null && !clientCN.isEmpty()){
                clientAuthnScheme = "tls_client_cert";
            }else if(clientAuthnSubject != null || responseMessage != null){
                clientAuthnScheme = "client_ip";
            }else{
                clientAuthnScheme = "no_auth";
            }
            if(appDomains != null){
                String[] domainsList = appDomains.split("\\|");
                for(String domain:domainsList){
                    if(proxyBasePath.startsWith(domain)){
                        appDomain = domain;
                        break;
                    }
                }
            }
            if(apiKeyIssueAt != null){
                clientCredCreateTS = ft.format(Long.parseLong(apiKeyIssueAt));
            } 
            if(oauthTokenIssueAt != null){
                clientCredCreateTS = ft.format(Long.parseLong(oauthTokenIssueAt));
                clientCredExpireTS = ft.format(reqTime + ((Long.parseLong(oauthTokenExpiresIn))*1000));
                clientCredTTL = oauthTokenExpiresIn + "Seconds.";
            }
            if(clientAuthnScheme.equalsIgnoreCase("tls_client_cert")){
            try {
                String pemEncoded = messageContext.getVariable("tls.client.raw.cert").toString().replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----", "");
                decodedPem = Base64.getMimeDecoder().decode(pemEncoded);
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decodedPem));
                clientCredTTL = calculateCertTTL(cert);
                clientCredCreateTS = ft.format(cert.getNotBefore().getTime());
                clientCredExpireTS = ft.format(cert.getNotAfter().getTime());
            } catch (Exception e) {
                e.printStackTrace();
            }
            }
            String accessControl = apiProxyName;
            if(apiproductName != null){
                accessControl = apiproductName + "/" +apiProxyName;
            }
            if(spSentTime != null){
                spReqTS = ft.format(spSentTime);
            }
            if(spSentTime != null){
                spRespTS = ft.format(spReceivedTime);
                spElapsedTime = (spReceivedTime-spSentTime)+"ms";
            }
            String audit = String.valueOf("ReqTS="+reqTS + ", Environment=" + environment  +", HttpRespErrMessage=" +responseMessage + 
                        ", SpReqTS= " + spReqTS +  ", SpRespTS=" + spRespTS + ", ClientAuthnSubject=" +clientAuthnSubject + ", ClientAuthnScheme="+clientAuthnScheme +  ", ClientIP="+clientIp + 
                        ", IPCtx=" + ipContext + ", ClientCredId=" +clientCredId+ ", ClientCredExpireTS=" +clientCredExpireTS + ", ClientCredCreateTS=" +clientCredCreateTS +
                        ", ClientCredTTL=" + clientCredTTL + ", ReqMethod=" + reqMethod + ", ReqURL=" + requestUri + ", TargetURL=" + targetURL + ", EndpointCtx=" +endpointContext+  ", AppDomainName=" + appDomain +
                        ", OAuthToken="+ oauthToken + ", AccessControls=" + accessControl + ", SpElapsedTime="+ spElapsedTime +  ", HttpRespCode=" + httpResposeCode).replace("null", "");
            messageContext.setVariable("ucla.audit.info", audit);
            return ExecutionResult.SUCCESS;
        } catch (Exception e) {
            return ExecutionResult.ABORT;
        }
	}

    private String calculateCertTTL(X509Certificate cert) {
        long certTTL = (cert.getNotAfter().getTime()-cert.getNotBefore().getTime());
        StringBuilder ttl = new StringBuilder("");
				if (certTTL > YEAR) {
					ttl.append(certTTL / YEAR).append(" years ");
					certTTL %= YEAR;
				}
				if (certTTL > DAY) {
					ttl.append(certTTL / DAY).append(" days ");
					certTTL %= DAY;
				}
				if (certTTL > HOUR) {
					ttl.append(certTTL / HOUR).append(" hours ");
					certTTL %= HOUR;
				}
				if (certTTL > MINUTE) {
					ttl.append(certTTL / MINUTE).append(" minutes ");
					certTTL %= MINUTE;
				}
				if (certTTL > SECOND) {
					ttl.append(certTTL / SECOND).append(" seconds ");
					certTTL %= SECOND;
				}
        return ttl.toString();
    }

    
}