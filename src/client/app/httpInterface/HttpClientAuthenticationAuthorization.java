package client.app.httpInterface;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import client.app.crypto.CryptographicOperations;
import client.app.util.Constants;

public class HttpClientAuthenticationAuthorization {
	
	private static String ticket;
	private static String aeTarget = null;
	final static int port = 8080;

	public static void ECQVregistration() {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		URI uri = null;
		try {
			uri = new URIBuilder()
					.setScheme("http")
					.setHost("localhost")
					.setPort(port)
					.setPath("/AuthorizationServer/ECQVClientRegistration")
					.build();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String encodedU = CryptographicOperations.getUfromRandom();
		
		/* Create the json body for the request */
		JsonObject jsonBody = new JsonObject();
		jsonBody.addProperty("clientID", Constants.clientID);
		jsonBody.addProperty("U", encodedU);
		Gson gson = new GsonBuilder().create();
		String body = gson.toJson(jsonBody);
		
		/* Create the http post request */
		HttpPost httpPostRequest = new HttpPost(uri);
		StringEntity entity = new StringEntity(body,
				ContentType.create("application/json", Consts.UTF_8));
		httpPostRequest.setEntity(entity);
		try {
			CloseableHttpResponse response = httpClient.execute(httpPostRequest);
			HttpEntity respEntity = response.getEntity();
			if(respEntity != null) {
				String respContent = EntityUtils.toString(respEntity);
				
				System.out.println("Response content: " + respContent);
				
				/* Get the content from the json object */
				JsonParser parser = new JsonParser();
			    JsonObject jsonRespBody = parser.parse(respContent).getAsJsonObject();
			    
			    String clientCertificate = jsonRespBody.get("certificate").getAsString();
			    String q = jsonRespBody.get("q").getAsString();
			    String pubKeyDAS = jsonRespBody.get("pubKey") .getAsString();
			    
			    System.out.println("Client certificate: " + clientCertificate);
			    System.out.println("q value: " + q);
			    System.out.println("Public key of DAS server: " + pubKeyDAS);
			    
			    /* Generate the key pair */
				CryptographicOperations.generateECKeyPair(clientCertificate, q);
				
				/* Verify public key correctness */
				boolean verify = CryptographicOperations.verifyPublicKey(clientCertificate, pubKeyDAS);
				if(verify==true) {
					System.out.println("The client public key has been verified successfully!");
				}else {
					System.out.println("Closing the connection...");
					response.close();
					System.out.println("An attacker modified the data sent over the http channel!");
				}
			}
			System.out.println("Response status code: " + response.getStatusLine().getStatusCode());
			httpClient.close();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static String resourceRegistration(String resName, String typeSub) {
		String msg = "empty";
		String err = "false";
		CloseableHttpClient httpClient = HttpClients.createDefault();
		URI uri = null;
		try {
			uri = new URIBuilder()
					.setScheme("http")
					.setHost("localhost")
					.setPort(port)
					.setPath("/AuthorizationServer/ResourceClientRegistration")
					.build();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String[] data = CryptographicOperations.generateResourceRegistraionMaterial(resName, typeSub).split("\\|");
		
		String Tr = data[0];
		String subscription = data[1];
		String nonce = data[2];
		String encodeZ= data[3];
		
		/* Create the json body for the request */
		JsonObject jsonBody = new JsonObject();
		//jsonBody.addProperty("clientID", Constants.clientID);
		jsonBody.addProperty("timestamp", Tr);
		jsonBody.addProperty("subscription", subscription);
		jsonBody.addProperty("nonce", nonce);
		jsonBody.addProperty("encodeZ", encodeZ);
		Gson gson = new GsonBuilder().create();
		String body = gson.toJson(jsonBody);
		
		System.out.println("Payload: " + body);
		
		/* Create the http post request */
		HttpPost httpPostRequest = new HttpPost(uri);
		StringEntity entity = new StringEntity(body,
				ContentType.create("application/json", Consts.UTF_8));
		httpPostRequest.setEntity(entity);
		CloseableHttpResponse response;
		try {
			response = httpClient.execute(httpPostRequest);
			HttpEntity respEntity = response.getEntity();
			// Parse the response if it is not empty
			if(respEntity != null) {
				// Retrieve the payload
				String respContent = EntityUtils.toString(respEntity);
				if(response.getStatusLine().getStatusCode() != 400) {
					// Retrieve the ticket from the payload
					JsonParser parser = new JsonParser();
					JsonObject jsonRespBody = parser.parse(respContent).getAsJsonObject();

					if(jsonRespBody.has("message")) {
						msg = jsonRespBody.get("message").getAsString();
					}
					ticket = jsonRespBody.get("ticket").getAsString();
					System.out.println("Access ticket: " + ticket);
				}else {
					msg = respContent;
					err = "true";
					System.out.println("Error message: " + msg);
					httpClient.close();
					return msg;
				}
			}
			System.out.println("Response status code: " + response.getStatusLine().getStatusCode());
			httpClient.close();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return msg + "|" + err;
	}
	
	public static String sendAuthenticationAndAuthorizationRequest() {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		String rxTimestamp = null;
		String sessionKey = null;
		URI uri = null;
		try {
			uri = new URIBuilder()
					.setScheme("http")
					.setHost("localhost")
					.setPort(9998)
					.build();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String Qu = CryptographicOperations.createAuthIdentity();
		
		/* Create the json body for the request */
		JsonObject jsonBody = new JsonObject();
		jsonBody.addProperty("clientID", Constants.clientID);
		jsonBody.addProperty("Qu", Qu);
		jsonBody.addProperty("ticket", ticket);
		Gson gson = new GsonBuilder().create();
		String body = gson.toJson(jsonBody);
		
		System.out.println("Authentication request: " + body);
		/* Create the http post request */
		HttpPost httpPostRequest = new HttpPost(uri);
		StringEntity entity = new StringEntity(body,
				ContentType.create("application/json", Consts.UTF_8));
		httpPostRequest.setEntity(entity);
		try {
			CloseableHttpResponse response = httpClient.execute(httpPostRequest);
			String responseData = EntityUtils.toString(response.getEntity());
			EntityUtils.consume(response.getEntity());
			System.out.println("Response: " + responseData);
			System.out.println("Response status code: " + response.getStatusLine().getStatusCode());
			
			// Parse the json payload
		    JsonParser parser = new JsonParser();
		    JsonObject jsonReqBody = parser.parse(responseData).getAsJsonObject();
		    
		    // Save the timestamp Ts and the uri of the resource in variables
		    aeTarget = jsonReqBody.get("aeTarget").getAsString();
		    rxTimestamp = jsonReqBody.get("timestamp").getAsString();
		    
		    sessionKey = CryptographicOperations.generateSymmetricSessionKey(rxTimestamp);
			
			httpClient.close();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return sessionKey;
	}
	
	public static String getAeTarget() {
		return aeTarget;
	}
}
