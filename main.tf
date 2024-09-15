terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
}

variable "ssh_private_key_path" {
  description = "Path to the SSH private key"
  type        = string
}

provider "digitalocean" {
  token = var.do_token
}

data "digitalocean_ssh_key" "SSH_Key" {
  name = "SSH_Key"
}

resource "digitalocean_droplet" "The-Hive" {
  name   = "The-Hive"
  image  = "ubuntu-22-04-x64"
  size   = "s-1vcpu-1gb"
  region = "lon1"
  tags   = ["The-Hive"]

  ssh_keys = [data.digitalocean_ssh_key.SSH_Key.id]
}

resource "digitalocean_project" "The-Hive" {
  name        = "TheHive"
  description = "The-Hive Security Platform"
  purpose     = "CyberSecurity Project"
  environment = "Production"
  resources   = [digitalocean_droplet.TheHive.urn]
}