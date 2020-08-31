/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.auth0.client.model;

import com.google.gson.Gson;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.wso2.auth0.client.Auth0Constants;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIConstants;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Auth0APIKeyInterceptor implements RequestInterceptor {
    private Auth0AccessTokenResponse accessTokenInfo;


    public Auth0APIKeyInterceptor(String tokenEndpoint, String consumerKey, String consumerSecret, String audience)
            throws IOException {
        HttpClient httpClient = HttpClientBuilder.create().useSystemProperties().build();
        HttpPost httpPost = new HttpPost(tokenEndpoint);
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        parameters.add(new BasicNameValuePair(Auth0Constants.GRANT_TYPE,
                Auth0Constants.GRANT_TYPE_CLIENT_CREDENTIALS));
        parameters.add(new BasicNameValuePair(Auth0Constants.AUDIENCE, audience));
        byte[] credentials = org.apache.commons.codec.binary.Base64
                .encodeBase64((consumerKey + ":" + consumerSecret).getBytes(StandardCharsets.UTF_8));
        httpPost.setHeader(APIConstants.AUTHORIZATION_HEADER_DEFAULT, APIConstants.AUTHORIZATION_BASIC
                + new String(credentials, StandardCharsets.UTF_8));
        httpPost.setEntity(new UrlEncodedFormEntity(parameters));
        HttpResponse response = httpClient.execute(httpPost);
        int statusCode = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            new APIManagementException(String.format(Auth0Constants.STRING_FORMAT,
                    Auth0Constants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
        }
        if (HttpStatus.SC_OK == statusCode) {
            try (InputStream inputStream = entity.getContent()) {
                String content = IOUtils.toString(inputStream);
                accessTokenInfo = new Gson().fromJson(content, Auth0AccessTokenResponse.class);
            }
        }
    }

    @Override
    public void apply(RequestTemplate requestTemplate) {
        requestTemplate.header("Authorization", "Bearer ".concat(accessTokenInfo.getAccessToken()));
    }
}
