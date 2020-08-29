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

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

public class Auth0ResourceServerInfo {
    @SerializedName("name")
    private String name;
    @SerializedName("identifier")
    private String identifier;
    @SerializedName("scopes")
    private List<String> scopes = new ArrayList<>();
    @SerializedName("signing_alg")
    private String signingAlg;
    @SerializedName("signing_secret")
    private String signingSecret;
    @SerializedName("allow_offline_access")
    private boolean allowOfflineAccess;
    @SerializedName("token_lifetime")
    private long tokenLifetime;
    @SerializedName("enforce_policies")
    private boolean enforcePolicies;
    @SerializedName("token_dialect")
    private String tokenDialect;
    @SerializedName("client")
    private Object client;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public String getSigningAlg() {
        return signingAlg;
    }

    public void setSigningAlg(String signingAlg) {
        this.signingAlg = signingAlg;
    }

    public String getSigningSecret() {
        return signingSecret;
    }

    public void setSigningSecret(String signingSecret) {
        this.signingSecret = signingSecret;
    }

    public boolean isAllowOfflineAccess() {
        return allowOfflineAccess;
    }

    public void setAllowOfflineAccess(boolean allowOfflineAccess) {
        this.allowOfflineAccess = allowOfflineAccess;
    }

    public long getTokenLifetime() {
        return tokenLifetime;
    }

    public void setTokenLifetime(long tokenLifetime) {
        this.tokenLifetime = tokenLifetime;
    }

    public boolean isEnforcePolicies() {
        return enforcePolicies;
    }

    public void setEnforcePolicies(boolean enforcePolicies) {
        this.enforcePolicies = enforcePolicies;
    }

    public String getTokenDialect() {
        return tokenDialect;
    }

    public void setTokenDialect(String tokenDialect) {
        this.tokenDialect = tokenDialect;
    }

    public Object getClient() {
        return client;
    }

    public void setClient(Object client) {
        this.client = client;
    }
}
