# ReflectiveNAS

ReflectiveNAS is a version control and file synchronization utility that keeps track of changes made to files and synchronizes those changes across multiple servers, making it easy to keep backups across multiple locations and to view and restore old revisions of files. ReflectiveNAS is designed to operate effectively on slow or unstable internet connections.

ReflectiveNAS is designed to act as a lightweight "middle layer" which sits between any file system of your choice and any "front end" of your choice such as SSH/SSHFS. ReflectiveNAS focuses solely on unobtrusively adding version control and synchronization while interoperating with whichever methods for compression, encryption, remote access, etc you prefer.

The ReflectiveNAS server runs on Linux and Windows (via WSL or Cygwin) and clients can be anything capable of remotely accessing files on the server through your application of choice.


## Installation

Install Python and [reFUSE](https://github.com/pleiszenburg/refuse). Copy `config.example.json` to `config.json` and edit the config file with your desired settings. You will need an SSL certificate for your server. You can use an existing certificate or, by installing and using OpenSSL, you can generate a new one via `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 99999 -noenc`.


## Usage

Run `python ReflectiveNAS.py` to launch the server. Use `python tools.py` to search for files and to retrieve old versions of files.
