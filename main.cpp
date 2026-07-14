#include <drogon/drogon.h>
#include <iostream>

int main() {
    std::cout << "Starting PaliCap Engine on port 8080..." << std::endl;
    drogon::app()
        .addListener("0.0.0.0", 8080)
        .setThreadNum(1)
        .run();
    return 0;
}
