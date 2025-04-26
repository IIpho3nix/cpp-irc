#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
typedef int socket_t;
#endif

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <fstream>
#include <vector>
#include <cstring>

std::atomic<bool> running{true};
std::string server_auth_secret;

void xorEncryptDecrypt(std::string &data, const std::vector<unsigned char> &key)
{
    for (size_t i = 0; i < data.size(); ++i)
    {
        data[i] ^= key[i % key.size()];
    }
}

void receive_messages(socket_t sock, const std::vector<unsigned char> &key)
{
    char buffer[2048];
    while (running)
    {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_received > 0)
        {
            std::string msg(buffer, bytes_received);
            xorEncryptDecrypt(msg, key);
            std::cout << msg;
            std::cout.flush();
        }
        else if (bytes_received == 0)
        {
            std::cout << "\nServer closed the connection.\n";
            running = false;
            break;
        }
        else
        {
            std::cerr << "\nError receiving data.\n";
            running = false;
            break;
        }
    }
}

std::vector<unsigned char> load_key(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open key file.");

    std::vector<unsigned char> key((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());

    if (key.empty())
        throw std::runtime_error("Key file is empty.");

    return key;
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cout << "Usage: " << argv[0] << " <server_ip> <port> <keyfile>\n";
        return 1;
    }

    const char *server_ip = argv[1];
    int port = std::stoi(argv[2]);
    std::string keyfile = argv[3];

    std::vector<unsigned char> xorKey;
    try
    {
        xorKey = load_key(keyfile);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error loading key: " << e.what() << '\n';
        return 1;
    }

    server_auth_secret = std::string(xorKey.end() - 16, xorKey.end());

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
#endif

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address\n";
        return 1;
    }

    if (connect(sock, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Connection failed\n";
        return 1;
    }

    std::cout << "Connected to server. Sending encrypted handshake...\n";

    xorEncryptDecrypt(server_auth_secret, xorKey);
    if (send(sock, server_auth_secret.c_str(), server_auth_secret.size(), 0) == -1)
    {
        std::cerr << "Failed to send auth\n";
        return 1;
    }

    char auth_response[2048] = {0};
    int bytes = recv(sock, auth_response, sizeof(auth_response), 0);
    if (bytes <= 0)
    {
        std::cerr << "Failed to receive auth response\n";
        return 1;
    }

    std::string reply(auth_response, bytes);
    xorEncryptDecrypt(reply, xorKey);
    if (reply != "accepted")
    {
        std::cerr << "Authentication failed: " << reply << "\n";
        return 1;
    }

    std::cout << "Authenticated. Secure channel established.\n";

    std::thread receiver(receive_messages, sock, xorKey);

    std::string input;
    while (running && std::getline(std::cin, input))
    {
        if (input.empty())
            continue;

        input += "\n";
        xorEncryptDecrypt(input, xorKey);

        if (send(sock, input.c_str(), input.size(), 0) == -1)
        {
            std::cerr << "Error sending data\n";
            break;
        }
    }

    running = false;

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif

    if (receiver.joinable())
        receiver.join();

    std::cout << "Disconnected.\n";
    return 0;
}
