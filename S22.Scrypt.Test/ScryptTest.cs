using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using System.Linq;
using System;

namespace S22.Scrypt.Test {
	/// <summary>
	/// Contains unit-tests for the Rfc7914DerivedBytes class.
	/// </summary>
	/// <remarks>
	/// The test vectors have been taken from RFC 7914, Chapter 12 "Test Vectors for scrypt", p.12.
	/// </remarks>
	[TestClass]
	public class ScryptTest {
		/// <summary>
		/// First test vector for the scrypt function. Cp. RFC 7914, page 12.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void Rfc7914TestVector0() {
			var P = Encoding.ASCII.GetBytes(string.Empty);
			var S = Encoding.ASCII.GetBytes(string.Empty);
			int N = 16,
				r = 1,
				p = 1,
				dkLen = 64;
			var expected = new byte[] {
				0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
				0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
				0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
				0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06
			};
			using(var scrypt = new Rfc7914DerivedBytes(P, S, r, p, N)) {
				Assert.IsTrue(scrypt.GetBytes(dkLen).SequenceEqual(expected));
			}
		}

		/// <summary>
		/// Second test vector for the scrypt function. Cp. RFC 7914, page 12.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void Rfc7914TestVector1() {
			var P = Encoding.ASCII.GetBytes("password");
			var S = Encoding.ASCII.GetBytes("NaCl");
			int N = 1024,
				r = 8,
				p = 16,
				dkLen = 64;
			var expected = new byte[] {
				0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
				0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
				0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
				0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d, 0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
			};
			using (var scrypt = new Rfc7914DerivedBytes(P, S, r, p, N)) {
				Assert.IsTrue(scrypt.GetBytes(dkLen).SequenceEqual(expected));
			}
		}

		/// <summary>
		/// Third test vector for the scrypt function. Cp. RFC 7914, page 12.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void Rfc7914TestVector2() {
			var P = Encoding.ASCII.GetBytes("pleaseletmein");
			var S = Encoding.ASCII.GetBytes("SodiumChloride");
			int N = 16384,
				r = 8,
				p = 1,
				dkLen = 64;
			var expected = new byte[] {
				0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
				0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
				0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
				0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87
			};
			using (var scrypt = new Rfc7914DerivedBytes(P, S, r, p, N)) {
				Assert.IsTrue(scrypt.GetBytes(dkLen).SequenceEqual(expected));
			}
		}

		/// <summary>
		/// Fourth test vector for the scrypt function. Cp. RFC 7914, page 12.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void Rfc7914TestVector3() {
			var P = Encoding.ASCII.GetBytes("pleaseletmein");
			var S = Encoding.ASCII.GetBytes("SodiumChloride");
			int N = 1048576,
				r = 8,
				p = 1,
				dkLen = 64;
			var expected = new byte[] {
				0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae, 0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8, 0x81,
				0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d, 0xab, 0xe5, 0xee, 0x98, 0x20, 0xad, 0xaa, 0x47,
				0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f, 0xfa, 0x1c, 0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3,
				0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb, 0xcb, 0xf4, 0x5c, 0x6f, 0xa7, 0x7a, 0x41, 0xa4
			};
			using (var scrypt = new Rfc7914DerivedBytes(P, S, r, p, N)) {
				Assert.IsTrue(scrypt.GetBytes(dkLen).SequenceEqual(expected));
			}
		}

		/// <summary>
		/// Ensures passing invalid arguments to the constructor throws the appropriate
		/// argument exceptions.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void InvalidArgumentsForCtor() {
			AssertThrows<ArgumentNullException>(() => new Rfc7914DerivedBytes((byte[])null, null),
				"A password of null was inappropriately allowed.");
			AssertThrows<ArgumentNullException>(() => new Rfc7914DerivedBytes("", null),
				"A salt of null was inappropriately allowed.");
			var S = Encoding.ASCII.GetBytes(string.Empty);
			AssertThrows<ArgumentException>(() => new Rfc7914DerivedBytes("", S, 0),
				"A block size less than or equal to 0 was inappropriately allowed.");
			var r = 8;
			AssertThrows<ArgumentException>(() => new Rfc7914DerivedBytes("", S, r, -1),
				"A parallelization less than 0 was inappropriately allowed.");
			var p = 0;
			AssertThrows<ArgumentException>(() => new Rfc7914DerivedBytes("", S, r, p, 0),
				"A cost less than or equal to 0 was inappropriately allowed.");
		}

		/// <summary>
		/// Ensures passing an invalid argument to the GetBytes method throws an
		/// <see cref="ArgumentOutOfRangeException"/>.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void InvalidArgumentForGetBytes() {
			var P = Encoding.ASCII.GetBytes("pleaseletmein");
			var S = Encoding.ASCII.GetBytes("SodiumChloride");
			using (var scrypt = new Rfc7914DerivedBytes(P, S)) {
				AssertThrows<ArgumentOutOfRangeException>(() => scrypt.GetBytes(-1),
				"A negative number was inappropriately allowed as argument.");
			}
		}

		/// <summary>
		/// Ensures assigning null to the <see cref="Rfc7914DerivedBytes.Salt"/> property
		/// throws an <see cref="ArgumentNullException"/>.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void InvalidValueForSalt() {
			var P = Encoding.ASCII.GetBytes(string.Empty);
			var S = Encoding.ASCII.GetBytes(string.Empty);
			using (var scrypt = new Rfc7914DerivedBytes(P, S)) {
				AssertThrows<ArgumentNullException>(() => {
					scrypt.Salt = null;
				}, "A salt value of null was inappropriately allowed.");
			}
		}

		/// <summary>
		/// Ensures that assigning an invalid value to the <see cref="Rfc7914DerivedBytes.BlockSize"/>
		/// property throws an <see cref="ArgumentException"/>.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void InvalidValueForBlockSize() {
			var P = Encoding.ASCII.GetBytes(string.Empty);
			var S = Encoding.ASCII.GetBytes(string.Empty);
			using (var scrypt = new Rfc7914DerivedBytes(P, S)) {
				AssertThrows<ArgumentException>(() => {
					scrypt.BlockSize = 0;
				}, "A block size value of 0 was inappropriately allowed.");
				AssertThrows<ArgumentException>(() => {
					scrypt.BlockSize = -1;
				}, "A negative block size value was inappropriately allowed.");
			}
		}

		/// <summary>
		/// Ensures that assigning an invalid value to the <see cref="Rfc7914DerivedBytes.Cost"/>
		/// property throws an <see cref="ArgumentException"/>.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void InvalidValueForCost() {
			var P = Encoding.ASCII.GetBytes(string.Empty);
			var S = Encoding.ASCII.GetBytes(string.Empty);
			using (var scrypt = new Rfc7914DerivedBytes(P, S)) {
				AssertThrows<ArgumentException>(() => {
					scrypt.Cost = 0;
				}, "A cost value of 0 was inappropriately allowed.");
				AssertThrows<ArgumentException>(() => {
					scrypt.Cost = 1;
				}, "A cost value of 1 was inappropriately allowed.");
				AssertThrows<ArgumentException>(() => {
					scrypt.Cost = -1;
				}, "A negative cost value was inappropriately allowed.");
				AssertThrows<ArgumentException>(() => {
					scrypt.Cost = 12345;
				}, "A cost value that is not a power of two was inappropriately allowed.");
			}
		}

		/// <summary>
		/// Ensures that assigning an invalid value to the <see cref="Rfc7914DerivedBytes.Parallelization"/>
		/// property throws an <see cref="ArgumentException"/>.
		/// </summary>
		[TestMethod]
		[TestCategory("Scrypt")]
		public void InvalidValueForParallelization() {
			var P = Encoding.ASCII.GetBytes(string.Empty);
			var S = Encoding.ASCII.GetBytes(string.Empty);
			using (var scrypt = new Rfc7914DerivedBytes(P, S)) {
				AssertThrows<ArgumentException>(() => {
					scrypt.Parallelization = -1;
				}, "A negative parallelization value was inappropriately allowed.");
			}
		}

		/// <summary>
		/// Verifies that the specified exception is thrown by the specified method.
		/// </summary>
		/// <typeparam name="T">
		/// The type of the expected exception.
		/// </typeparam>
		/// <param name="action">
		/// Encapsulates the method that is expected to throw the specified exception.
		/// </param>
		/// <param name="message">
		/// A message to display if the assertion fails. This message can be seen in the
		/// unit test results.
		/// </param>
		static void AssertThrows<T>(Action action, string message = null) where T:Exception {
			try {
				action();
				Assert.Fail(message);
			} catch(T) {
			}
		}
	}
}
