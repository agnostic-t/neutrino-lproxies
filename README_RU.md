![[logo]](./assets/logo.png)

Русский | [English](./README.md)

# Проект Neutrino

Данный репозиторий относится к проекту [Neutrino](https://github.com/agnostic-t/neutrino-core), является базовой реализацией модуля `local`.

## Содержание

На данный момент содержит реализации:

- [socks5](./socks5/socks5.go): SOCKS5 прокси, поддерживает методы CONNECT и UDP ASSOCIATE. Может использоваться в связке с TUN режимом.

Планируется добавлене:

- `http`: HTTP прокси
- `https`: HTTPS прокси
