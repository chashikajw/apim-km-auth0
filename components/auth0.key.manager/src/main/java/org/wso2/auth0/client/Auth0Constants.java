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

package org.wso2.auth0.client;

public class Auth0Constants {
    public static final String AUTH0_TYPE = "Auth0";
    public static final String SCOPE = "scope";
    public static final String AZP = "azp";
    public static final String AUTH0_DISPLAY_NAME = "Auth0";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String AUDIENCE = "audience";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTH0_RESOURCE_SERVER = "WSO2 resource server API";
    public static final String CONTENT_TYPE = "Content-type";
    public static final String CONTENT_TYPE_JSON = "application/json";
    public static final String STRING_FORMAT = "%s %s";
    public static final String APP_TYPE = "app_type";
    public static final String DEFAULT_CLIENT_APPLICATION_TYPE = "regular_web";
    public static final String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
    public static final String ERROR_COULD_NOT_READ_HTTP_ENTITY = "Could not read http entity for response";
    public static final String ERROR_ENCODING_METHOD_NOT_SUPPORTED = "Encoding method is not supported";
    public static final String ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER = "Error has occurred while reading " +
            "or closing buffer reader";
    public static final long DEFAULT_TOKEN_LIFETIME = 86400;
}
