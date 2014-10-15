ccrypt-j
========

This is a Java library for encrypting and decrypting files compatible with the [ccrypt](http://ccrypt.sourceforge.net/) command line tool. It uses the [Bouncy Castle](http://bouncycastle.org/) as the cipher implementation.

## Goals

* Straight forward and simple to use Java API (v0.1)
* Support for using ccrypt in Camel Routes (v0.2)

## Usage

### Adding ccrypt-j to your project

TODO Maven dependencies
TODO Manual download and addition

### Encrypting a file using ccrypt-j

TODO

### Decrypting a file using ccrypt-j

TODO

## Building from source

Prerquisites
- JDK 1.7 or later has been installed
- Maven 3 has been installed
Steps
- Clone the Github project:
```
git clone https://github.com/chrsoo/ccrypt-j.git
```
- Change to the git repository and run Maven:
```
mvn install
```

## FAQ

### Why implement ccrypt in Java?
When integrating a java based application with a system that encrypts files using ccrypt using the command line tool can be very costly. Each time a JNI call is made the entire Java process forked, consuming large amount of memory and CPU. In addition using JNI to decrypt and then pass the decrypted file to to a normal Java class is a clunky solution. With standard IO Streams encryption and decryption is straight forward and simple.

### With ccrypt versions are supperted by ccrypt-j?
Only the latest version (1.10) of ccrypt is supported. Possibly it can work with older versions but this has not been verified.

### What cipher is used in ccrypt/ccrypt-j
The Rijndael 256-bit cipher with CFB is used. This is the same that is used in AES but there are minor incompatibilities between the AES standard and the ccrypt implementation. In particular a 256 bit IV is used instead of the 128 bit IV mandated by AES (or at least it is the only IV supported by JCE...)