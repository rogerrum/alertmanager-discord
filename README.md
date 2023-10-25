Alertmanager Discord Webhook
========

[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/rogerrum/alertmanager-discord)](https://hub.docker.com/r/rogerrum/alertmanager-discord/tags)
[![license](https://img.shields.io/github/license/rogerrum/alertmanager-discord)](https://github.com/rogerrum/alertmanager-discord/blob/main/LICENSE)
[![DockerHub pulls](https://img.shields.io/docker/pulls/rogerrum/alertmanager-discord.svg)](https://hub.docker.com/r/rogerrum/alertmanager-discord/)
[![DockerHub stars](https://img.shields.io/docker/stars/rogerrum/alertmanager-discord.svg)](https://hub.docker.com/r/rogerrum/alertmanager-discord/)
[![GitHub stars](https://img.shields.io/github/stars/rogerrum/alertmanager-discord.svg)](https://github.com/rogerrum/alertmanager-discord)
[![Contributors](https://img.shields.io/github/contributors/rogerrum/alertmanager-discord.svg)](https://github.com/rogerrum/alertmanager-discord/graphs/contributors)
[![Paypal](https://img.shields.io/badge/donate-paypal-00457c.svg?logo=paypal)](https://www.paypal.com/donate/?business=CRVGAN4YGG9KL&no_recurring=0&item_name=rogerrum&currency_code=USD)




A minimal docker image with golang application, which listens for Prometheus Alertmanager's notifications and pushes them to Discord channel.

Repository name in Docker Hub: **[rogerrum/alertmanager-discord](https://hub.docker.com/r/rogerrum/alertmanager-discord/)**  
Published via **automated build** mechanism  


Give this a webhook (with the DISCORD_WEBHOOK environment variable) and point it as a webhook on alertmanager, and it will post your alerts into a discord channel for you as they trigger:

![img.png](https://raw.githubusercontent.com/rogerrum/alertmanager-discord/main/.github/demo-img.png)

## Environment configuration variables
```properties
DISCORD_WEBHOOK=<webhook, where to post alerts. For more details see: https://support.discordapp.com/hc/en-us/articles/228383668-Intro-to-Webhooks>
DISCORD_USERNAME=<override bot name at Discord>
DISCORD_AVATAR_URL=<override avatar url at Discord (optional)>
LISTEN_ADDRESS=<address and port to listen on (default:127.0.0.1:9094)>
VERBOSE=ON <(Optional - logs request and response)>
```

## Warning

This program is not a replacement to alertmanager, it accepts webhooks from alertmanager, not prometheus.

The standard "dataflow" should be:

```
Prometheus -------------> alertmanager -------------------> alertmanager-discord

alerting:                 receivers:                         
  alertmanagers:          - name: 'discord_webhook'         environment:
  - static_configs:         webhook_configs:                   - DISCORD_WEBHOOK=https://discordapp.com/api/we...
    - targets:              - url: 'http://localhost:9094'     - DISCORD_USERNAME=<override username if needed>
       - 127.0.0.1:9093                                        - DISCORD_AVATAR_URL=<override avatar url if needed>





```

## Example alertmanager config:

```
global:
  # The smarthost and SMTP sender used for mail notifications.
  smtp_smarthost: 'localhost:25'
  smtp_from: 'alertmanager@example.org'
  smtp_auth_username: 'alertmanager'
  smtp_auth_password: 'password'

# The directory from which notification templates are read.
templates: 
- '/etc/alertmanager/template/*.tmpl'

# The root route on which each incoming alert enters.
route:
  group_by: ['alertname']
  group_wait: 20s
  group_interval: 5m
  repeat_interval: 3h 
  receiver: discord_webhook

receivers:
- name: 'discord_webhook'
  webhook_configs:
  - url: 'http://localhost:9094'
```

For more details see: https://prometheus.io/docs/alerting/configuration/  


## Inspired by
* https://github.com/benjojo/alertmanager-discord
