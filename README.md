# S22.Scrypt

### Introduction

This repository contains a .NET library that implements the password-based key derivation function scrypt specified in [RFC 7914](https://tools.ietf.org/html/rfc7914). 



### Usage & Examples

To use the library add the S22.Scrypt.dll assembly to your project references in Visual Studio. Here's
a simple example which instantiates a new instance of the Rfc7914DeriveBytes class and uses it to
derive a sequence of bytes from a password.

	using System;
	using S22.Scrypt;

	namespace Test {
		class Program {
			static void Main(string[] args) {
				using (var scrypt = new Rfc7914DeriveBytes("myPassword", Encoding.ASCII.GetBytes("someSalt"))) {
					var derivedBytes = scrypt.GetBytes(1234);
				}
			}
		}
	}



### Credits

This library is copyright © 2016 Torben Könke.



### License

This library is released under the [MIT license](https://github.com/smiley22/S22.Sasl/blob/master/License.md).



### Bug reports

Please send your bug reports to [smileytwentytwo@gmail.com](mailto:smileytwentytwo@gmail.com) or create a new
issue on the GitHub project homepage.
