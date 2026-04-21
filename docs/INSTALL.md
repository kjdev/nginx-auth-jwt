# Installation Guide

## Prerequisites

### Required Libraries

- [jansson](http://www.digip.org/jansson/) — header and library
- [OpenSSL](http://www.openssl.org/) — header and library

### Package Installation Examples

#### Debian/Ubuntu

```bash
apt-get install -y libjansson-dev libssl-dev
```

#### RHEL/CentOS/Fedora

```bash
dnf install -y jansson-devel openssl-devel
```

#### Alpine Linux

```bash
apk add --no-cache jansson-dev openssl-dev
```

## Building from Source

### Step 1: Clone the repository

Clone with submodules so the `nxe-json` dependency is fetched alongside the module:

```bash
git clone --recursive https://github.com/kjdev/nginx-auth-jwt
cd nginx-auth-jwt
```

If you already cloned without `--recursive`, initialize the submodules explicitly:

```bash
git submodule update --init --recursive
```

### Step 2: Download nginx source

```bash
NGINX_VERSION=1.x.x
wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
tar -zxf nginx-${NGINX_VERSION}.tar.gz
```

### Step 3: Enter the nginx source directory

```bash
cd nginx-${NGINX_VERSION}
```

### Step 4: Configure with the dynamic module

```bash
./configure --add-dynamic-module=../
```

### Step 5: Build

```bash
make
```

### Step 6: Install

```bash
make install
```

After installation, load the module in `nginx.conf`:

```nginx
load_module modules/ngx_http_auth_jwt_module.so;
```

## Docker

Build the image:

```bash
docker build -t nginx-auth-jwt .
```

Run with a custom configuration:

```bash
docker run -p 80:80 -v $PWD/app.conf:/etc/nginx/http.d/default.conf nginx-auth-jwt
```

A pre-built image is available from GitHub Packages:

```bash
docker pull ghcr.io/kjdev/nginx-auth-jwt/nginx
```

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Configuration examples
- [INSTALL.md](INSTALL.md): Installation guide
- [SECURITY.md](SECURITY.md): Security considerations
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
