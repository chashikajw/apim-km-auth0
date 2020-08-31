package org.wso2.auth0.client.model;

import feign.Headers;
import feign.RequestLine;

public interface Auth0ResourceServer {
    @RequestLine("POST")
    @Headers("Content-Type: application/json")
    public Auth0ResourceServerInfo createResourceServer(Auth0ResourceServerInfo resourceServerInfo);
}
