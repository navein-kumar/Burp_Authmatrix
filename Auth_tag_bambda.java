int port = requestResponse.request().httpService().port();

if (!requestResponse.request().hasHeader("X-Session-Tag")) {
    if (port == 8080) {
        return requestResponse.request().withAddedHeader("X-Session-Tag", "admin");
    } else if (port == 8081) {
        return requestResponse.request().withAddedHeader("X-Session-Tag", "user");
    }
}
return requestResponse.request();
