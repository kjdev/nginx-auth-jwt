
ARG ALPINE_VERSION=3.16

FROM ghcr.io/kjdev/nginx-auth-jwt as auth-jwt
FROM ghcr.io/kjdev/nginx-keyval as keyval

### nginx ###
FROM alpine:${ALPINE_VERSION} as nginx

RUN apk --no-cache upgrade \
 && apk --no-cache add \
      hiredis \
      jansson \
      nginx \
      nginx-mod-http-js \
 && sed \
      -e 's/^user /#user /' \
      -e 's@^error_log .*$@error_log /dev/stderr warn;@' \
      -e 's@access_log .*;$@access_log /dev/stdout main;@' \
      -i /etc/nginx/nginx.conf \
 && rm -f /etc/nginx/http.d/default.conf \
 && mkdir -p /etc/nginx/conf.d \
 && mkdir -p /var/cache/nginx \
 && chown -R nginx. /etc/nginx/conf.d /etc/nginx/http.d /var/cache/nginx

COPY --from=auth-jwt /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so /usr/lib/nginx/modules/
COPY --from=auth-jwt /etc/nginx/modules/auth_jwt.conf /etc/nginx/modules/
COPY --from=keyval /usr/lib/nginx/modules/ngx_http_keyval_module.so /usr/lib/nginx/modules/
COPY --from=keyval /etc/nginx/modules/keyval.conf /etc/nginx/modules/

USER nginx
CMD ["nginx", "-g", "daemon off;"]

COPY --chown=nginx:nginx frontend.conf /etc/nginx/http.d/
COPY --chown=nginx:nginx openid_connect.server_conf /etc/nginx/conf.d/
COPY --chown=nginx:nginx openid_connect_configuration.conf /etc/nginx/http.d/
COPY --chown=nginx:nginx openid_connect.js /etc/nginx/conf.d/

ARG CLIENT_ID
ARG CLIENT_SECRET
ARG REDIRECT_URI=/_codexch

RUN sed \
      -e "s@/_codexch@${REDIRECT_URI}@g" \
      -i /etc/nginx/conf.d/openid_connect.server_conf \
 && sed \
      -e "s/CLIENT_ID/${CLIENT_ID}/" \
      -e "s/CLIENT_SECRET/${CLIENT_SECRET}/" \
      -i /etc/nginx/http.d/openid_connect_configuration.conf
