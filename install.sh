#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker is not installed. Installing Docker..."
    
    # Install Docker using official Docker installation script
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
else
    echo "Docker is installed."
fi

# Pull the Docker image
echo "Pulling Docker image..."
docker pull strangebee/thehive

# Start the Docker container
echo "Starting Docker container..."
docker run -d strangebee/thehive