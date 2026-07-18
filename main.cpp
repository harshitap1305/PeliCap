#include <drogon/drogon.h>
#include <iostream>
#include <csignal>

int main() {
    signal(SIGPIPE, SIG_IGN);
    std::cout << "Starting PaliCap Engine on port 8080..." << std::endl;
    drogon::app()
        .registerPreRoutingAdvice([](const drogon::HttpRequestPtr &req, drogon::FilterCallback &&defer, drogon::FilterChainCallback &&chain) {
            if (req->method() == drogon::Options) {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k200OK);
                resp->addHeader("Access-Control-Allow-Origin", "*");
                resp->addHeader("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PUT, DELETE");
                resp->addHeader("Access-Control-Allow-Headers", "Content-Type");
                defer(resp);
            } else {
                chain();
            }
        })
        .registerPostHandlingAdvice([](const drogon::HttpRequestPtr &req, const drogon::HttpResponsePtr &resp) {
            resp->addHeader("Access-Control-Allow-Origin", "*");
            resp->addHeader("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PUT, DELETE");
            resp->addHeader("Access-Control-Allow-Headers", "Content-Type");
        })
        .addListener("0.0.0.0", 8080)
        .setThreadNum(1)
        .run();
    return 0;
}
