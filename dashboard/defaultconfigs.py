NGINX_DEFAULT_CONFIG = r"""
    user  root;
    worker_processes  auto;

    error_log  /var/log/nginx/error.log notice;
    pid        /var/run/nginx.pid;

    events {
        worker_connections  1024;
    }

    http {
        include       /etc/nginx/mime.types;
        default_type  application/octet-stream;
        real_ip_header X-Forwarded-For;
        set_real_ip_from 127.0.0.1;       # If traffic is coming from localhost (proxy sidecar)
        set_real_ip_from 10.0.0.0/8;
        real_ip_recursive on;
        log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                          '$status $body_bytes_sent "$http_referer" '
                          '"$http_user_agent" "$http_x_forwarded_for"';

        access_log  /var/log/nginx/access.log  main;
        port_in_redirect off;
        sendfile        on;
        keepalive_timeout  65;
        include /etc/nginx/conf.d/*.conf;

        server {
            listen       8080 default_server;
            server_name  _;
            client_max_body_size 150M;
                root   /usr/share/nginx/html; # Ensure your document root is correctly set
                index  index.php index.html index.htm;

    location / {
        #try_files $uri $uri/ =404;
        try_files $uri $uri/ /index.php?$args;
    }

            location ~ \.php$ {
                try_files $uri =404;
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass php-svc:9001;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_param PATH_INFO $fastcgi_path_info;
                fastcgi_param HTTPS on;
            }

            error_page   500 502 503 504  /50x.html;
            location = /50x.html {
                root   /usr/share/nginx/html;
            }
        }
    }
"""
