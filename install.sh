#!/bin/bash

if ! command -v docker &> /dev/null
then
    echo "Docker is not installed. Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
else
    echo "Docker is installed."
fi
echo "Pulling Docker image..."
docker pull strangebee/thehive
echo "Starting Docker container..."
docker run -d strangebee/thehive