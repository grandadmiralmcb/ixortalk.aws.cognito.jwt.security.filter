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
package com.ixortalk.aws.cognito.boot.filter;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.ixortalk.aws.cognito.boot.JwtAuthentication;
import com.ixortalk.aws.cognito.boot.config.JwtConfiguration;
import com.ixortalk.aws.cognito.boot.config.JwtIdTokenCredentialsHolder;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;

public class AwsCognitoIdTokenProcessor {

    private static final Log logger = LogFactory.getLog(AwsCognitoIdTokenProcessor.class);

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String EMPTY_PWD = "";

    @Autowired
    private JwtConfiguration jwtConfiguration;

    @Autowired
    private ConfigurableJWTProcessor configurableJWTProcessor;

    @Autowired
    private JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;
    


    public Authentication getAuthentication(HttpServletRequest request) throws Exception {

        String idToken = request.getHeader(jwtConfiguration.getHttpHeader());
        if (idToken != null) {

            JWTClaimsSet claimsSet = null;
            if (idToken.contains("Bearer "))
	        {
	            	idToken = idToken.split("Bearer ")[1];
	        }
        
            claimsSet = configurableJWTProcessor.process(idToken, null);

            if (!isIssuedCorrectly(claimsSet)) {
                throw new Exception(String.format("Issuer %s in JWT token doesn't match cognito idp %s", claimsSet.getIssuer(), jwtConfiguration.getCognitoIdentityPoolUrl()));
            }

            if (!isIdToken(claimsSet)) {
                throw new Exception("JWT Token doesn't seem to be an ID Token");
            }

            String username = claimsSet.getClaims().get(jwtConfiguration.getUserNameField()).toString();
            System.out.println("Username in this version:"+ username);
            if (username != null) {
            	List<GrantedAuthority> grantedAuthorities = null;
                List<String> groups = (List<String>) claimsSet.getClaims().get(jwtConfiguration.getGroupsField());
                if (claimsSet.getClaims().containsKey(jwtConfiguration.getGroupsField()) && groups != null && groups.size() > 0) 
                	grantedAuthorities = convertList(groups, group -> new SimpleGrantedAuthority(ROLE_PREFIX + group.toUpperCase()));
                else
                {
                	grantedAuthorities = Arrays.asList(new SimpleGrantedAuthority(ROLE_PREFIX+"Anonymous"));
                }
                User user = new User(username, EMPTY_PWD, grantedAuthorities);

                jwtIdTokenCredentialsHolder.setIdToken(idToken);
                return new JwtAuthentication(user, claimsSet, grantedAuthorities);
            }
            
            //get a congito user identity from the userPool

            //register thread event to call every 58 minutes to refresh user token
            
        }

        logger.trace("No idToken found in HTTP Header");
        return null;
    }

    private boolean isIssuedCorrectly(JWTClaimsSet claimsSet) {
        return claimsSet.getIssuer().equals(jwtConfiguration.getCognitoIdentityPoolUrl());
    }

    private boolean isIdToken(JWTClaimsSet claimsSet) {
        return claimsSet.getClaim("token_use").equals("id");
    }

    private static <T, U> List<U> convertList(List<T> from, Function<T, U> func) {
        return from.stream().map(func).collect(Collectors.toList());
    }
}