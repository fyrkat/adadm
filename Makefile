doc: bin/phpdoc.phar
	php bin/phpdoc.phar -d src -t doc

bin/phpdoc.phar:
	mkdir -p bin
	curl -L https://github.com/phpDocumentor/phpDocumentor2/releases/download/v2.9.0/phpDocumentor.phar -o bin/phpdoc.phar

clean:
	rm -rf doc bin
