#!/usr/bin/env bash
g++-14 -o server server.cpp -pthread
g++-14 -o client client.cpp -pthread