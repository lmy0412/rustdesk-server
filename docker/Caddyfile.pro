rustdesk.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:21114
	header Strict-Transport-Security "max-age=31536000; includeSubDomains"
	request_body {
		max_size 2MB
	}
}
