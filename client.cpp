#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#else
#include <unistd.h>
#include <arpa/inet.h>
typedef int socket_t;
#endif

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>

std::atomic<bool> running{true};

void receive_messages(socket_t sock)
{
    char buffer[1024];
    while (running)
    {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0)
        {
            std::cout << std::string(buffer, bytes_received);
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

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cout << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }

    const char *server_ip = argv[1];
    int port = std::stoi(argv[2]);

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

    std::cout << "Connected to server.\n";

    std::thread receiver(receive_messages, sock);

    std::string input;
    while (running && std::getline(std::cin, input))
    {
        if (input.empty())
            continue;
        input += "\n";
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
