#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <regex>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <unistd.h>
#include <condition_variable>
#include <vector>

using namespace std;

template<typename T>
class SafeQueue {
public:
    void push(T value) {
        lock_guard<mutex> lock(mtx);
        q.push(value);
        cv.notify_one();
    }

    bool pop(T &value) {
        unique_lock<mutex> lock(mtx);
        cv.wait(lock, [this]{ return !q.empty(); });
        value = q.front();
        q.pop();
        return true;
    }

private:
    queue<T> q;
    mutex mtx;
    condition_variable cv;
};

string ipToString(const struct sockaddr_in& addr) {
    char buffer[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &(addr.sin_addr), buffer, INET_ADDRSTRLEN);
}

string hashIP(const struct sockaddr_in& addr) {
    string ipString = ipToString(addr);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, ipString.c_str(), ipString.length());
    SHA256_Final(hash, &ctx);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setfill('0') << setw(2) << (int)hash[i];
    }
    return ss.str();
}

struct ClientConnection {
    int socketDescriptor;
    string hashedIP;
};

struct CachedResponse {
    string headers;
    string body;
    time_t timestamp;

    bool isValid(time_t currentTime, int maxAge = 3600) const {
        return difftime(currentTime, timestamp) <= maxAge;
    }
};

SafeQueue<ClientConnection> clientQueue;
unordered_map<string, CachedResponse> cache;
regex filterRegex(".*(example.com|blocked.com).*");
mutex cacheMutex;

bool isBlocked(const string& url) {
    regex blockedRegex(".*(example.com).*");
    return regex_search(url, blockedRegex);
}

string extractHostFromRequest(const string& request) {
    regex hostRegex("Host: ([^\\s]+)");
    smatch match;
    if (regex_search(request, match, hostRegex)) {
        return match[1];
    }
    return "";
}

void handleClient(ClientConnection connection) {
    cout << "Handling client with hashed IP: " << connection.hashedIP << endl;

    int clientSocket = connection.socketDescriptor;

    char requestBuffer[4096];
    ssize_t bytesRecv = recv(clientSocket, requestBuffer, sizeof(requestBuffer) - 1, 0);

    if (bytesRecv <= 0) {
        perror("recv");
        close(clientSocket);
        return;
    }

    requestBuffer[bytesRecv] = '\0';
    string request(requestBuffer);

    string requestURL;
    stringstream ss(request);
    string method;
    ss >> method;
    ss >> requestURL;

    {
        lock_guard<mutex> lock(cacheMutex);
        if (cache.count(requestURL) > 0) {
            time_t currentTime = time(nullptr);
            if (cache[requestURL].isValid(currentTime)) {
                string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
                response += cache[requestURL].body;
                send(clientSocket, response.c_str(), response.length(), 0);
                cout << "Using cached response for " << requestURL << endl;
                close(clientSocket);
                return;
            }
        }
    }

    if (isBlocked(requestURL)) {
        string response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAccess Denied";
        send(clientSocket, response.c_str(), response.length(), 0);
        cout << "Blocked request for URL: " << requestURL << endl;
        close(clientSocket);
        return;
    }

    string targetHost = extractHostFromRequest(request);
    if (targetHost.empty()) {
        string response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nBad Request";
        send(clientSocket, response.c_str(), response.length(), 0);
        close(clientSocket);
        return;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(targetHost.c_str(), "80", &hints, &res) != 0) {
        string response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found";
        send(clientSocket, response.c_str(), response.length(), 0);
        close(clientSocket);
        return;
    }

    int targetSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(targetSocket, res->ai_addr, res->ai_addrlen) < 0) {
        string response = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nBad Gateway";
        send(clientSocket, response.c_str(), response.length(), 0);
        close(clientSocket);
        close(targetSocket);
        freeaddrinfo(res);
        return;
    }

    freeaddrinfo(res);

    send(targetSocket, request.c_str(), request.length(), 0);

    char responseBuffer[4096];
    ssize_t responseBytes = recv(targetSocket, responseBuffer, sizeof(responseBuffer) - 1, 0);
    if (responseBytes > 0) {
        responseBuffer[responseBytes] = '\0';
        string serverResponse(responseBuffer);

        send(clientSocket, serverResponse.c_str(), serverResponse.length(), 0);

        lock_guard<mutex> lock(cacheMutex);
        cache[requestURL] = { "", serverResponse, time(nullptr) };
    }

    close(targetSocket);
    close(clientSocket);
}

void workerThread(int threadID) {
    cout << "Worker thread " << threadID << " started" << endl;
    while (true) {
        ClientConnection connection;
        clientQueue.pop(connection);
        cout << "Worker thread " << threadID << " handling connection for hashed IP: " << connection.hashedIP << endl;
        handleClient(connection);
    }
}

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return 1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8080);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind");
        return 1;
    }

    socklen_t addrLen = sizeof(serverAddr);
    if (getsockname(serverSocket, (struct sockaddr*)&serverAddr, &addrLen) == -1) {
        perror("getsockname");
        return 1;
    }
    cout << "Server is listening on port " << ntohs(serverAddr.sin_port) << endl;

    if (listen(serverSocket, 10) < 0) {
        perror("listen");
        return 1;
    }

    const int numWorkers = 4;
    vector<thread> workers;
    for (int i = 0; i < numWorkers; ++i) {
        workers.emplace_back(workerThread, i + 1);
    }

    while (true) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            perror("accept");
            continue;
        }

        ClientConnection connection = { clientSocket, hashIP(clientAddr) };
        cout << "Accepted connection from " << ipToString(clientAddr) << " with hashed IP: " << connection.hashedIP << endl;
        clientQueue.push(connection);
    }

    return 0;
}
