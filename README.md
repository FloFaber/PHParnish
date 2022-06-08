# PHParnish

PHP tool for working with Varnish reverse proxy cache.
Fork of the original, deprecated, un-maintained [php-varnish](https://github.com/timwhitlock/php-varnish)

* Author: [Flo Faber](https://flofaber.com/)
* See [varnish-cache.org](http://varnish-cache.org/) for information about Varnish
	
## Admin socket

This package includes an admin socket class, which PHP applications can use to interface with the **varnishadm** program.  
Common tasks would include checking the health of caches and purging when site content needs refreshing.

## Todo

* Add short cut methods for all admin commands
* Sanitise admin command parameters, such as regexp

## License

The whole PHParnish package, is released under the MIT license, see LICENSE.
