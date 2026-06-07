![[logo]](./assets/logo.png)

English | [Русский](./README_RU.md)

# Project Neutrino  

This repository belongs to the [Neutrino](https://github.com/agnostic-t/neutrino-core) project, it is the base implementation of the `local` module.

## Content

Currently it contains implementations:

- [socks5](./socks5/socks5.go): SOCKS5 proxy, supports CONNECT and UDP ASSOCIATE methods. It can be used in combination with TUN mode.

Planned proxies:

- `http`: HTTP proxy
- `https`: HTTPS proxy
