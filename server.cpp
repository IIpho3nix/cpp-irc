#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#else
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#endif

#include <cctype>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <cstring>
#include <mutex>
#include <map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <any>
#include <algorithm>
#include <stdexcept>

std::mutex clients_mutex;
std::vector<socket_t> clients;
std::map<std::string, socket_t> sockets;
std::mutex sockets_mutex;
std::vector<unsigned char> xorKey;
std::string server_auth_secret;

std::map<std::string, std::any> config;

std::vector<unsigned char> load_xor_key(const std::string &filepath)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open XOR key file: " + filepath);
    }

    std::vector<unsigned char> key(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    if (key.empty())
    {
        throw std::runtime_error("XOR key file is empty: " + filepath);
    }

    return key;
}

void xorEncryptDecrypt(std::string &data, const std::vector<unsigned char> &key)
{
    for (size_t i = 0; i < data.size(); ++i)
    {
        data[i] ^= key[i % key.size()];
    }
}

bool xor_send(socket_t client_socket, const std::string &message, const std::vector<unsigned char> &key)
{
    std::string encrypted = message;
    xorEncryptDecrypt(encrypted, key);

    auto sent = send(client_socket, encrypted.c_str(), encrypted.size(), 0);
    return sent == encrypted.size();
}

std::string xor_recv(socket_t client_socket, const std::vector<unsigned char> &key)
{
    char buffer[2048] = {0};
    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0)
    {
        throw std::runtime_error("Failed to receive data");
        return "";
    }

    std::string decrypted(buffer, bytes_received);
    xorEncryptDecrypt(decrypted, key);
    return decrypted;
}

bool xorDecrypt(std::vector<unsigned char> &data, const std::vector<unsigned char> &key)
{
    if (key.empty())
        return false;
    for (size_t i = 0; i < data.size(); ++i)
    {
        data[i] ^= key[i % key.size()];
    }
    return true;
}

void load_config(const std::string &filename = "config.env")
{
    try
    {
        std::ifstream env_file(filename);
        if (!env_file.is_open())
        {
            std::cerr << "Failed to open " << filename << std::endl;
            exit(1);
        }
        std::string line;
        while (std::getline(env_file, line))
        {
            if (line.empty() || line[0] == '#')
                continue;
            auto pos = line.find('=');
            if (pos == std::string::npos)
                continue;
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            if (key == "port")
            {
                config[key] = std::stoi(value);
                continue;
            }

            config[key] = value;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error loading config: " << e.what() << std::endl;
        exit(1);
    }
}

bool containsControlSequences(const std::string &str)
{
    for (char c : str)
    {
        if (std::iscntrl(c))
        {
            return true;
        }
    }
    return false;
}

void broadcast_message(const std::string &message)
{
    try
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (socket_t client : clients)
        {
            xor_send(client, message, xorKey);
        }
        std::cout << message;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error broadcasting message: " << e.what() << std::endl;
    }
}

std::string get_timestamp()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = duration_cast<std::chrono::seconds>(duration).count();

    seconds %= 86400;
    int hours = seconds / 3600;
    seconds %= 3600;
    int minutes = seconds / 60;

    std::ostringstream oss;
    oss << "\033[90m[" << std::setw(2) << std::setfill('0') << hours << ":"
        << std::setw(2) << std::setfill('0') << minutes << "]\033[0m ";

    return oss.str();
}

bool authenticate(socket_t client_socket, const std::vector<unsigned char> &xorKey)
{
    try
    {
        char buffer[1024] = {0};
        int bytes_received = recv(client_socket, buffer, 1024, 0);
        if (bytes_received <= 0)
        {
            throw std::runtime_error("Failed to receive auth token");
            return false;
        }

        std::vector<unsigned char> encrypted(buffer, buffer + bytes_received);
        xorDecrypt(encrypted, xorKey);
        std::string message(encrypted.begin(), encrypted.end());
        message.erase(message.find_last_not_of(" \r\n") + 1);

        if (message == server_auth_secret)
        {
            std::string reply = "accepted";
            for (size_t i = 0; i < reply.size(); ++i)
                reply[i] ^= xorKey[i % xorKey.size()];
            send(client_socket, reply.c_str(), reply.size(), 0);
            return true;
        }
        else
        {
            std::string reply = "denied";
            for (size_t i = 0; i < reply.size(); ++i)
                reply[i] ^= xorKey[i % xorKey.size()];
            send(client_socket, reply.c_str(), reply.size(), 0);
            return false;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Authentication error: " << e.what() << std::endl;
        return false;
    }
}

bool handle_username(socket_t client_socket, std::string &username)
{
    try
    {
        xor_send(client_socket, "Enter username: ", xorKey);
        username = xor_recv(client_socket, xorKey).c_str();
        auto pos = username.find('\n');
        if (pos != std::string::npos)
            username.erase(pos);

        pos = username.find('\r');
        if (pos != std::string::npos)
            username.erase(pos);

        std::replace(username.begin(), username.end(), ' ', '_');
        xor_send(client_socket, "Username accepted.\n", xorKey);
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error handling username: " << e.what() << std::endl;
        return false;
    }
}

void client_handler(socket_t client_socket)
{
    try
    {
        if (!authenticate(client_socket, xorKey))
        {
#ifdef _WIN32
            closesocket(client_socket);
#else
            close(client_socket);
#endif
            return;
        }

        std::string username;
        if (!handle_username(client_socket, username))
        {
#ifdef _WIN32
            closesocket(client_socket);
#else
            close(client_socket);
#endif
            return;
        }

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        getpeername(client_socket, (struct sockaddr *)&client_addr, &addr_len);
        char *client_ip = inet_ntoa(client_addr.sin_addr);

        int flag = 1;
        setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.push_back(client_socket);
        }

        {
            std::lock_guard<std::mutex> lock(sockets_mutex);
            sockets.insert({username, client_socket});
        }

        std::string login_msg = get_timestamp() + "[Server Message] <" + username + "> logged in from " + std::string(client_ip);
        broadcast_message(login_msg + "\n");

        std::string welcome_msg = get_timestamp() + "[Server Message] Welcome to " + std::any_cast<std::string>(config["server_name"]) + ", " + username + "! type /quit to quit, type /help for commands.";
        broadcast_message(welcome_msg + "\n");

        while (true)
        {
            std::string user_input = xor_recv(client_socket, xorKey);
            user_input.erase(user_input.find_last_not_of(" \n\r") + 1);

            if (user_input.empty())
            {
                continue;
            }

            if (containsControlSequences(user_input))
            {
                continue;
            }

            if (user_input.substr(0, 5) == "/quit")
            {
                std::string reason;
                if (user_input.length() < 6)
                {
                    reason = "Disconnected";
                }
                else
                {
                    reason = user_input.substr(6);
                }

                std::string exit_msg = get_timestamp() + "[Server Message] <" + username + "> has disconnected. (" + reason + ")";
                broadcast_message(exit_msg + "\n");

#ifdef _WIN32
                closesocket(client_socket);
#else
                close(client_socket);
#endif
                {
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    clients.erase(std::remove(clients.begin(), clients.end(), client_socket), clients.end());
                }

                {
                    std::lock_guard<std::mutex> lock(sockets_mutex);
                    sockets.erase(username);
                }

                break;
            }

            if (user_input.substr(0, 3) == "/me")
            {
                if (user_input.length() < 4)
                {
                    continue;
                }
                std::string me_msg = get_timestamp() + username + " " + user_input.substr(4);
                broadcast_message(me_msg + "\n");

                continue;
            }

            if (user_input.substr(0, 5) == "/nick")
            {
                if (user_input.length() < 6)
                {
                    continue;
                }
                std::string new_username = user_input.substr(6);
                std::string nick_msg = get_timestamp() + "[Server Message] <" + username + "> is now known as <" + new_username + ">.";

                {
                    std::lock_guard<std::mutex> lock(sockets_mutex);
                    sockets.erase(username);
                    sockets.insert({new_username, client_socket});
                }

                username = new_username;

                broadcast_message(nick_msg + "\n");
                continue;
            }

            if (user_input.substr(0, 4) == "/msg")
            {
                if (user_input.length() < 5)
                {
                    continue;
                }
                std::string args = user_input.substr(5);
                std::string target_username = args.substr(0, args.find(" "));
                args.erase(0, args.find(" ") + 1);

                if (target_username.empty())
                {
                    continue;
                }

                {
                    std::lock_guard<std::mutex> lock(sockets_mutex);
                    auto target_socket = sockets.find(target_username);
                    if (target_socket != sockets.end())
                    {
                        std::string message = get_timestamp() + "[Private Message] <" + username + "> -> <" + target_username + ">: " + args;
                        std::string sendmsg = message + "\n";
                        xor_send(target_socket->second, sendmsg, xorKey);
                        xor_send(client_socket, sendmsg, xorKey);

                        std::cout << message << std::endl;
                    }
                }

                continue;
            }

            if (user_input == "/ping")
            {
                std::string pong_msg = get_timestamp() + "[Server Message] Pong!\n";
                xor_send(client_socket, pong_msg, xorKey);
                continue;
            }

            if (user_input == "/help")
            {
                std::string help_msg = get_timestamp() + "[Server Message] Commands:\n";
                help_msg += "/quit (reason) - Disconnect from the server\n";
                help_msg += "/me [message] - Sends an action message\n";
                help_msg += "/nick [username] - Changes your username\n";
                help_msg += "/msg [username] [message] - Sends a private message\n";
                help_msg += "/ping - Responds with 'Pong!'\n";
                help_msg += "/help - Display this help message\n";
                xor_send(client_socket, help_msg, xorKey);
                continue;
            }

            std::string message = get_timestamp() + "<" + username + ">: " + user_input;

            broadcast_message(message + "\n");
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error in client handler: " << e.what() << std::endl;
        return;
    }
    finally:
    {
#ifdef _WIN32
        closesocket(client_socket);
#else
        close(client_socket);
#endif
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.erase(std::remove(clients.begin(), clients.end(), client_socket), clients.end());
        }

        std::string username;

        {
            std::lock_guard<std::mutex> lock(sockets_mutex);
            auto iter = sockets.begin();
            while (iter != sockets.end())
            {
                if (iter->second == client_socket)
                {
                    iter = sockets.erase(iter);
                    username = iter->first;
                }
                else
                {
                    ++iter;
                }
            }
        }

        if (!username.empty())
        {
            std::string exit_msg = get_timestamp() + "[Server Message] <" + username + "> has disconnected. (Connection closed)";

            broadcast_message(exit_msg + "\n");
        }
    }
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }
#endif

    if (argc >= 3 && std::string(argv[1]) == "--config")
    {
        load_config(argv[2]);
    }
    else
    {
        std::map<std::string, std::string> args;
        for (int i = 1; i < argc - 1; i += 2)
        {
            args[argv[i]] = argv[i + 1];
        }

        if (args.find("--server_name") == args.end() ||
            args.find("--port") == args.end() ||
            args.find("--keyfile") == args.end())
        {
            std::cerr << "Missing required arguments.\n";
            std::cerr << "Usage:\n";
            std::cerr << "  " << argv[0] << " --config <config_file>\n";
            std::cerr << "OR\n";
            std::cerr << "  " << argv[0] << " --server_name <name> --port <port> --keyfile <keyfile>\n";
            return 1;
        }

        config["server_name"] = args["--server_name"];
        config["port"] = std::stoi(args["--port"]);
        config["keyfile"] = args["--keyfile"];
    }

    xorKey = load_xor_key(std::any_cast<std::string>(config["keyfile"]));
    server_auth_secret = std::string(xorKey.end() - 16, xorKey.end());

    socket_t server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    try
    {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == -1)
        {
            throw std::runtime_error("Failed to create socket");
        }

        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) == -1)
        {
            throw std::runtime_error("Failed to set socket options");
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(std::any_cast<int>(config["port"]));

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1)
        {
            throw std::runtime_error("Bind failed");
        }

        if (listen(server_fd, 10) == -1)
        {
            throw std::runtime_error("Listen failed");
        }

        std::cout << "Server " << std::any_cast<std::string>(config["server_name"]) << " listening on port " << std::any_cast<int>(config["port"]) << "..." << std::endl;

        while (true)
        {
            new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
            if (new_socket == -1)
            {
                std::cerr << "Accept failed" << std::endl;
                continue;
            }

            std::thread(client_handler, new_socket).detach();
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error in server setup: " << e.what() << std::endl;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
