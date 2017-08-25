.. image:: https://travis-ci.org/xcir/libvmod-parseform.svg?branch=master
    :target: https://travis-ci.org/xcir/libvmod-parseform
.. image:: https://scan.coverity.com/projects/13538/badge.svg
    :target: https://scan.coverity.com/projects/xcir-libvmod-parseform

===============
vmod-parseform
===============


-------------------------------
Parse to POST request
-------------------------------

:Author: Shohei Tanaka(@xcir)
:Date: 2017-08-26
:Version: 51.2
:Support Varnish Version: 5.1.x
:Manual section: 3


SYNOPSIS
========

import parseform;

DESCRIPTION
===========

Get POST value

FUNCTIONS
=========

get
-----

Prototype
        ::

                get(STRING key, STRING glue=", ", ENUM { raw, urlencode } encode="raw")
Return value
	STRING
Description
	Get POST value.
	If POST have multiple-key, join with glue.
	Only used in vcl_recv.
	Need to call std.cache_req_body before using this.
	Support content-type is "application/x-www-form-urlencoded" and "multipart/form-data" and "text/plain".
Attention
	Does not care for binary, if set encode=raw.
	Output by percent encode, if set encode=urlencoded.
Example
        ::

                import std;
                import parseform;
                sub vcl_recv{
                    
                    std.cache_req_body(1MB);
                    if(parseform.get("postkey")){
                        ...
                    }
                }

get_blob
--------

Prototype
        ::

                get_blob(STRING key, STRING glue=", ", BOOL decode=false)
Return value
	BLOB
Description
	Get POST value.
	If POST have multiple-key, join with glue.
	Only used in vcl_recv.
	Need to call std.cache_req_body before using this.
	Support content-type is "application/x-www-form-urlencoded" and "multipart/form-data" and "text/plain".
	Decode the value, if decode is true and content-type is "application/x-www-form-urlencoded".


len
-----

Prototype
        ::

                len(STRING key, STRING glue=", ")
Return value
	INT
Description
	Get POST length.
	If POST have multiple-key, join with glue.
	Only used in vcl_recv.
	Need to call std.cache_req_body before using this.
	Support content-type is "application/x-www-form-urlencoded" and "multipart/form-data" and "text/plain".
Example
        ::

                import std;
                import parseform;
                sub vcl_recv{
                    
                    std.cache_req_body(1MB);
                    if(parseform.len("postkey") > 0){
                        ...
                    }
                }


urlencode
----------

Prototype
        ::

                urlencode(STRING txt)
Return value
	STRING
Description
	Encoding to Percent encode
Example
        ::

                import std;
                import parseform;
                sub vcl_recv{
                    
                    std.cache_req_body(1MB);
                    if(parseform.urlencode("foo.bar.~-_baz") == parseform.get(key="postkey", encode=urlencoded)){
                        ...
                    }
                }

urldecode
----------

Prototype
        ::

                urldecode(STRING txt)
Return value
	STRING
Description
	Decoding to Percent encode
Example
        ::

                import std;
                import parseform;
                sub vcl_recv{
                    
                    std.cache_req_body(1MB);
                    if(req.http.content-type == "application/x-www-form-urlencoded"){
                      if("foo bar" == parseform.urldecode(parseform.get("postkey"))){
                          ...
                      }
                    
                    }
                }

urlencode_blob
---------------

Prototype
        ::

                urlencode_blob(BLOB blob)
Return value
	STRING

urldecode_blob
---------------

Prototype
        ::

                urldecode_blob(STRING txt)
Return value
	BLOB

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the ``varnishtest`` tool.

Building requires the Varnish header files and uses pkg-config to find
the necessary paths.

Usage::

 ./autogen.sh
 ./configure

If you have installed Varnish to a non-standard directory, call
``autogen.sh`` and ``configure`` with ``PKG_CONFIG_PATH`` pointing to
the appropriate path. For instance, when varnishd configure was called
with ``--prefix=$PREFIX``, use

::

 export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
 export ACLOCAL_PATH=${PREFIX}/share/aclocal

The module will inherit its prefix from Varnish, unless you specify a
different ``--prefix`` when running the ``configure`` script for this
module.

Make targets:

* make - builds the vmod.
* make install - installs your vmod.
* make check - runs the unit tests in ``src/tests/*.vtc``.
* make distcheck - run check and prepare a tarball of the vmod.

If you build a dist tarball, you don't need any of the autotools or
pkg-config. You can build the module simply by running::

 ./configure
 make

Installation directories
------------------------

By default, the vmod ``configure`` script installs the built vmod in the
directory relevant to the prefix. The vmod installation directory can be
overridden by passing the ``vmoddir`` variable to ``make install``.

COMMON PROBLEMS
===============

* configure: error: Need varnish.m4 -- see README.rst

  Check whether ``PKG_CONFIG_PATH`` and ``ACLOCAL_PATH`` were set correctly
  before calling ``autogen.sh`` and ``configure``

* Incompatibilities with different Varnish Cache versions

  Make sure you build this vmod against its correspondent Varnish Cache version.
  For instance, to build against Varnish Cache 4.1, this vmod must be built from
  branch 4.1.

COPYRIGHT
=============

This document is licensed under the same license as the
libvmod-awsrest project. See LICENSE for details.

* Copyright (c) 2012-2017 Shohei Tanaka(@xcir)

request-body access based on libvmod-bodyaccess( https://github.com/aondio/libvmod-bodyaccess )
