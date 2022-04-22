/*******************************************************************************
 *  Copyright 2020 Deutsche Bank AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.db.bankapi.codesample;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * To run this application you have to change first 5 parameters to run this application:
 * The variables fkn and pin from one of your test user accounts as well as the value of the query
 * parameter "client_id" in Step1 with the clientId from one of your simulation apps which uses the authorization code
 * OAuth2 grant type and the query parameter "redirect_uri" with one corresponding redirectUri of your chosen app.
 *
 * To use the authorization code grant here, you additionally need the client secret of your created test app which
 * uses the authorization code grant type.
 *
 * To get the cash account transactions of an account of one of your selected testusers, your have
 * to provide the IBAN of this selected testuser.
 *
 * Check in this application, what is wrong and what is missing to get an access token from
 * the authorization code grant type from OAuth2.
 */
public class CallDbApiCashAccountTransactionsAuthCode {

    private final String SESSION_ID = "JSESSIONID";

    //The current session is stored in a cookie.
    private NewCookie sessionId;

    public static void main(String[] args) {

        CallDbApiCashAccountTransactionsAuthCode callDbApiCashAccount = new CallDbApiCashAccountTransactionsAuthCode();

        //Please login to activate your test user to get your fkn and pin
        String fkn = "Your FKN from on of your testusers";
        String pin = "Your PIN from one of your testusers";

        //Step 1
        Response response = callDbApiCashAccount.authorizationRequest();

        //Step 2
        Object [] responseAndRedirectUri = callDbApiCashAccount.redirectToLoginPage(response);

        //Step 3.1
        response = callDbApiCashAccount.loginAndAuthorize(responseAndRedirectUri, fkn, pin);

        //Step 3.2
        response = callDbApiCashAccount.grantAccess(response);

        //Step 4
        //What you have to do here?

        //Step 5
        //What you have to do here?

        String responseWithAccessToken  = response.readEntity(String.class);
        JsonObject jsonObject = JsonParser.parseString(responseWithAccessToken).getAsJsonObject();
        String accessToken = jsonObject.get("access_token").getAsString();

        //Step 6
        //Call the transactions with a given IBAN of your
        callDbApiCashAccount.callCashAccountsTransactions(accessToken);
    }

    /**
     * Step 1
     * Executes the OAuth2.0 initial authorization request.
     * Saves the session in a Cookie. Saving the session is optional and not part of
     * the OAuth2.0 specification!
     *
     * The scope request parameter is optional. The state request parameter is
     * optional too but recommended to e.g., increase the application's resilience
     * against CSRF attacks. All other request parameter are required!
     *
     * @return The {@link Response} from the OAuth2.0 initial authorization request.
     */
    private Response authorizationRequest() {

        WebTarget wt = ClientBuilder.newBuilder()
                //.connectTimeout(10, TimeUnit.SECONDS)
                //.readTimeout(10, TimeUnit.SECONDS)
                .build()
                .target("https://simulator-api.db.com/gw/oidc/authorize");

        //Please login to activate your client. The client_id and redirect_uri will be replaced with your activated client.
        Response response = wt.property(ClientProperties.FOLLOW_REDIRECTS, false)
                .queryParam("response_type", "has to be replaced with correct setting")
                .queryParam("client_id", "8b2030b0-7d64-4d89-bee8-c59fc071e778")
                .queryParam("redirect_uri", "Your redirect URI from your app")
                .queryParam("scope", "read_transactions")
                .queryParam("state", "0.21581183640296075")
                .request()
                .get();

        updateSessionId(response);
        System.out.println("Step 1 executed authorizeRequest.");
        return response;
    }

    /**
     * Step 2
     * Redirect to the login page and updating the session in the Cookie.
     *
     * @param response The {@link Response} from the initial OAuth2.0 authorization request.
     * @return An array which contains the {@link URI} and the {@link Response} from
     * the redirection.
     */
    private Object[] redirectToLoginPage(Response response) {
        /*
         * We have to follow the redirect manually here because the automatic
         * redirect in the HttpUrlConnection doesn't forward the cookie, i.e.
         */
        URI uri = response.getLocation();
        response =  ClientBuilder.newClient().target(uri)
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .request()
                .cookie(sessionId).get();

        updateSessionId(response);

        System.out.println("Step 2 executed redirected to login page.");
        return new Object[] {response, uri};
    }

    /**
     *  Step 3.1
     *  Executes the login with your default test users' fkn and pin and updates the session.
     *
     * @param responseAndRedirectUri contains the {@link Response} and {@link URI} from step 2.
     * @param username the fkn of your default test user.
     * @param password the pin of your default test user.
     * @return the {@link Response} after the login.
     */
    private Response loginAndAuthorize(Object [] responseAndRedirectUri, String username, String password) {
        Response response = (Response) responseAndRedirectUri[0];
        URI uri = (URI) responseAndRedirectUri[1];

        // extract CSRF token for this session
        String webPage = response.readEntity(String.class);
        String csrf = getCsrf(webPage);

        //get the action from the login page
        URI postUrl = getFormPostUrl(uri, webPage);
        // post login
        Form form = new Form();
        form.param("username", username);
        form.param("password", password);
        form.param("_csrf", csrf);
        form.param("submit", "Login");

        response = ClientBuilder.newClient().target(postUrl)
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .request()
                .cookie(sessionId)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

        updateSessionId(response);

        if(response.getLocation().toString().contains("noaccess")
                || response.getLocation().toString().contains("commonerror")
                || response.getLocation().toString().contains("failure")) {
            String message = response.readEntity(String.class);
            System.out.println("Failed to login as expected " + username + " loc = " + response.getLocation() + " msg = " + message);
        }

        System.out.println("Step 3.1 login with fkn and pin and authorization done.");
        return  response;
    }

    /**
     * Step 3.2
     * Updates the session.
     * Authorize access with the requested scope(s) in a dbAPI-prompted screen (consent screen).
     * The scope (read_accounts) was requested in Step 1.
     *
     * @param response The {@link Response} after the login from step 3.1.
     * @return The {@link Response} after authorize and give access for the (allowed) scope(s).
     */
    private Response grantAccess(Response response) {
        URI uri = response.getLocation();
        response = ClientBuilder.newClient().target(uri)
                .property(ClientProperties.FOLLOW_REDIRECTS, false)
                .request().cookie(sessionId).get();
        updateSessionId(response);

        // grant access
        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {

            String webPage = response.readEntity(String.class);
            String csrf = getCsrf(webPage);
            //get the action from the consent page
            URI postUrl = getFormPostUrl(uri, webPage);
            updateSessionId(response);

            // post consent
            Form form = new Form();
            form.param("user_oauth_approval", "true");
            form.param("_csrf", csrf);
            // give the consent once
            form.param("remember", "none");
            form.param("scope_read_transactions" , "read_transactions");

            response = ClientBuilder.newClient().target(postUrl).property(ClientProperties.FOLLOW_REDIRECTS, false)
                    .request().cookie(sessionId).post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

            System.out.println("Step 3.2 authorize access with requested scope read_accounts on consent screen.");
            return response;

        }
        return null;
    }

    /**
     * Step 4
     * Get the code fom the {@link Response} after successful authentication and given consent
     * of the scopes.
     *
     * @return The code.
     */
    public String getCode(Response response) {
        String responseLocationAfterGrantingAccess = response.getLocation().toString();
        return getCodeFromRedirect(responseLocationAfterGrantingAccess);
    }

    /**
     * Step 5
     * @TODO Request the access token from the code you recceive in Step 4
     *
     * @param code
     * @return The {@link Response} which contains the access token (bearer) in JSON format
     */
    private Response getAccessTokenFromCode(String code) {
        HttpAuthenticationFeature auth = HttpAuthenticationFeature.basic("client_id"
                , "client_secret");
        return requestAccessTokensFromCode(code, auth);
    }

    /**
     * Request access token with given code
     *
     * @param code
     * @return
     * @throws IOException
     */
    protected Response requestAccessTokensFromCode(String code, HttpAuthenticationFeature auth) {
        //TODO 1 Create a new Form object with the following form params:
        // grant_type -> authorization_code
        // code -> code
        // redirect_uri -> Your redirect URI from your app

        //TODO 2 Execute a POST request with the ClientBuilder.newClient() and set the following properties to this client to execute the request.
        //TODO 3 In the POST put the form as Entity.entity(form,MediaType.APPLICATION_FORM_URLENCODED_TYPE) so that the form params get's transmitted to the request
        //target -> https://simulator-api.db.com/gw/oidc/token
        //register -> auth
        //property -> ClientProperties.FOLLOW_REDIRECTS, false
        //request
        //post()


        updateSessionId(response);
        return response;
    }

    /**
     * Step 6
     * Call the cash accounts endpoint of the dbAPI to get the available cash accounts
     * from your default test users' account.
     * You should get 2 accounts from your default test users' account.
     *
     * @param accessToken The bearer token from Step 4.
     */
    private void callCashAccountsTransactions(String accessToken) {
        WebTarget wt = ClientBuilder.newBuilder()
                .build()
                .target("https://simulator-api.db.com/gw/dbapi/banking/transactions/v2")
                .queryParam("iban", "DE10010000000000008695");

        Response response = wt.request()
                .header("Authorization", "Bearer " + accessToken)
                .accept(MediaType.APPLICATION_JSON)
                .get();

        System.out.println("Calling dbAPI cashAccounts endpoint done. The JSON response is:");
        String jsonResponse = response.readEntity(String.class);
        System.out.println(jsonResponse);
    }

    /**
     * Helper method to extract the authorization code from given string
     *
     * @param uri
     * @return
     */
    protected String getCodeFromRedirect(String uri) {
        return getTokenFromString(uri, "code=([\\d\\w\\.-]+)&");
    }

    /**
     * Get sessionId from cookie from response and set local sessionId.
     *
     * @param response The current {@link Response}.
     */
    private void updateSessionId(Response response) {
        NewCookie cookie = response.getCookies().get(SESSION_ID);
        if(cookie != null) {
            sessionId = cookie;
        }
    }

    /**
     * Just for internal use to avoid potential CSRF attacks .
     * You can read the RFC against CSRF attacks here: https://tools.ietf.org/html/rfc6749.
     *
     * @param webPage The login or consent screen.
     * @return The CSRF code if found, null else.
     */
    static String getCsrf(String webPage) {
        Pattern p = Pattern.compile(" name=\"_csrf\" value=\"(.*?)\"");
        Matcher m = p.matcher(webPage);
        if ( m.find() ) {
            return m.group(1);
        }
        return null;
    }

    /**
     * Helper method. Get URI that is called from action in given HTML page.
     *
     * @param target  The target {@link URI}.
     * @param webPage The login or consent screen.
     * @return
     */
    protected URI getFormPostUrl(URI target, String webPage) {
        Pattern pattern = Pattern.compile("action=\"(.+?)\"");
        Matcher matcher = pattern.matcher(webPage);
        if ( matcher.find() ) {
            String uf = matcher.group(1);
            URI uri = URI.create(uf);
            if(!uri.isAbsolute()) {
                URI targetUri = target.resolve(uri);
                return targetUri;
            }
            return uri;
        }
        return null;
    }

    /**
     * Helper method. Get first match from given String.
     *
     * @param uri The string which have to be analyzed.
     * @param pattern The Regex-Pattern for searching.
     * @return Get the first match of the given String or null.
     */
    protected String getTokenFromString(String uri, String pattern) {
        Pattern tokenPattern = Pattern.compile(pattern);
        Matcher tokenMatcher = tokenPattern.matcher(uri);
        if (tokenMatcher.find()) {
            return tokenMatcher.group(1);
        }
        return null;
    }

}