#!/bin/bash

echo "Provisioning Droplet..."
terraform init
terraform apply -auto-approve

# Geting the public IP address of the provisioned Droplet
droplet_ip=$(terraform output -json | jq -r '.droplet_ipv4_address.value')

echo "Running post-provisioning tasks on the Droplet..."
ssh root@$droplet_ip 'bash -s' < install.sh