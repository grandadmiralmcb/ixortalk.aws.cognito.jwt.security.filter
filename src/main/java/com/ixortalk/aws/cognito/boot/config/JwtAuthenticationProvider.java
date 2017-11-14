/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-present IxorTalk CVBA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.ixortalk.aws.cognito.boot.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;



public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}


/*
public void authenticate(final String userID, final AuthenticationHandler authenticationHandler) {
	final CognitoUser user;

	if (userID == null || userID.isEmpty()) {
		user = userPool.getCurrentUser();
		if (user.getUserId() == null)
			return;
	} else
		user = userPool.getUser(userID);

	user.getSessionInBackground(new AuthenticationHandler() {
		@Override
		public void onSuccess(final CognitoUserSession session, final CognitoDevice device) {
			final Map<String, String> logins = new HashMap<String, String>();
			logins.put("cognito-idp." + _Configuration.AMAZON_COGNITO_REGION_STRING + ".amazonaws.com/"
					+ _Configuration.AMAZON_COGNITO_USER_POOL_ID, session.getIdToken().getJWTToken());
			credentialsProvider.withLogins(logins);
			handler.postDelayed(runnable, refreshEvery);
			// Init any additional services that use Cognitor
		}

		@Override
		public void getAuthenticationDetails(AuthenticationContinuation authenticationContinuation, String UserId) {
			authenticationHandler.getAuthenticationDetails(authenticationContinuation, UserId);
		}

		@Override
		public void getMFACode(MultiFactorAuthenticationContinuation continuation) {
			authenticationHandler.getMFACode(continuation);
		}

		@Override
		public void authenticationChallenge(ChallengeContinuation continuation) {
			authenticationHandler.authenticationChallenge(continuation);
		}

		@Override
		public void onFailure(Exception exception) {
			authenticationHandler.onFailure(exception);
		}
	});
}

private void regenerateCognitoTokens() {
	// If using Cognito User Pool with Identity pool, you must first generate a new
	// user session. This then creates the new Cognito Identy Pool token
	userPool.getCurrentUser().getSessionInBackground(new AuthenticationHandler() {
		@Override
		public void onSuccess(final CognitoUserSession session, final CognitoDevice device) {
			credentialsProvider.clear();
			final Map<String, String> logins = new HashMap<String, String>();
			logins.put("cognito-idp." + _Configuration.AMAZON_COGNITO_REGION_STRING + ".amazonaws.com/"
					+ _Configuration.AMAZON_COGNITO_USER_POOL_ID, session.getIdToken().getJWTToken());
			credentialsProvider.setLogins(logins);
			/*
			 * // Uncomment if you want to test the creation of the credentials, but it's
			 * not necessary. // I tested a dynamodb call 7 minutes after the hour, and it
			 * handled fine. new Thread(){
			 * 
			 * @Override //run off the main thread public void run(){ try{
			 * Log.d(LOG,"Cognito ID: "+credentialsProvider.getIdentityId());
			 * Log.d(LOG,"Cognito Credentials: "+credentialsProvider.getCredentials()); }
			 * catch (Exception e){ e.printStackTrace(); } } }.start();
			 *
		}

		@Override
		public void getAuthenticationDetails(final AuthenticationContinuation authenticationContinuation,
				final String UserId) {
			authenticationContinuation.continueTask();
		}

		@Override
		public void getMFACode(final MultiFactorAuthenticationContinuation continuation) {
			continuation.continueTask();
		}

		@Override
		public void authenticationChallenge(final ChallengeContinuation continuation) {
			continuation.continueTask();
		}

		@Override
		public void onFailure(final Exception e) {
			e.printStackTrace();
		}
	});
}

final private Handler handler = new Handler();
final private Runnable runnable = new Runnable() {
	@Override
	public void run() {
		regenerateCognitoTokens();
		handler.postDelayed(this, refreshEvery);
	}
};*/