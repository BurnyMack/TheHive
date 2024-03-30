#!/bin/bash

# Pull the Docker image and run it
echo "Pulling Docker image..."
docker pull strangebee/thehive
echo "Starting Docker container..."
docker run -d strangebee/thehive