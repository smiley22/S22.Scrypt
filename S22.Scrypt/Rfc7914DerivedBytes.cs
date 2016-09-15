// Comment out if you want to compile a version that is somewhat slower but does not require
// the /unsafe switch.
#define UNSAFE

using System;
using System.Security.Cryptography;
using System.Text;

namespace S22.Scrypt {
	/// <summary>
	/// Implements the password-based key derivation function scrypt.
	/// </summary>
	public class Rfc7914DerivedBytes : DeriveBytes {
		byte[] salt;
		int blockSize;
		int cost;
		int parallelization;

		/// <summary>
		/// Gets or sets the key salt value for the operation.
		/// </summary>
		/// <exception cref="ArgumentNullException">
		/// The property is being set and the new salt value is null.
		/// </exception>
		/// <remarks>
		/// Salt, a random set of bytes, is used to make unauthorized decrypting of a message more
		/// difficult. A dictionary attack is an attack in which the attacker attempts to decrypt
		/// an encrypted message by comparing the encrypted value with previously computed
		/// encrypted values for the most likely keys. This attack is made much more difficult by
		/// the introduction of salt, or random bytes, at the end of the password before the key
		/// derivation.
		/// </remarks>
		public byte[] Salt {
			get {
				return salt;
			}
			set {
				if (value == null)
					throw new ArgumentNullException("The Salt property cannot be null.");
				salt = (byte[])value.Clone();
			}
		}

		/// <summary>
		/// Gets or sets the block size parameter for the operation.
		/// </summary>
		/// <remarks>
		/// At the current time (August 2016), a block size of 8 appears to yield good results.
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is less than or equal to 0.
		/// </exception>
		public int BlockSize {
			get {
				return blockSize;
			}
			set {
				if (value < 1)
					throw new ArgumentException($"Invalid value {value} for BlockSize.");
				blockSize = value;
			}
		}

		/// <summary>
		/// Gets or sets the CPU/Memory cost parameter for the operation.
		/// </summary>
		/// <remarks>
		/// The CPU/Memory cost parameter must be larger than 1, a power of 2, and less than
		/// 2^(128 * <see cref="BlockSize"/> / 8).
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is less than or equal to 1, or the new
		/// value is not a power of 2.
		/// </exception>
		public int Cost {
			get {
				return cost;
			}
			set {
				if ((value < 2) || ((value & (value - 1)) != 0))
					throw new ArgumentException($"Invalid value {value} for Cost.");
				cost = value;
			}
		}

		/// <summary>
		/// Gets or sets the Parallelization parameter for the operation.
		/// </summary>
		/// <remarks>
		/// The parallelization parameter is a positive integer less than or equal to
		/// ((2^32-1) * 32) / (128 * <see cref="BlockSize"/>).
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is negative.
		/// </exception>
		public int Parallelization {
			get {
				return parallelization;
			}
			set {
				if (value < 0)
					throw new ArgumentException($"Invalid value {value} for Parallelization.");
				parallelization = value;
			}
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt,
		/// and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="salt">
		/// The key salt used to derive the key.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter or the <paramref name="salt"/> parameter is
		/// null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="blockSize"/> parameter is less than one, or the
		/// <paramref name="parallelization"/> is less than one, or the <paramref name="cost"/>
		/// parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(byte[] password, byte[] salt, int blockSize = 8,
			int parallelization = 1, int cost = 16384) {
			if (password == null)
				throw new ArgumentNullException(nameof(password));
			Salt = salt;
			BlockSize = blockSize;
			Parallelization = parallelization;
			Cost = cost;
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt
		/// size, and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="saltSize">
		/// The size of the random salt that you want the class to generate.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="saltSize"/> parameter is less than 1, or the <paramref name="blockSize"/>
		/// parameter is less than one, or the <paramref name="parallelization"/> is less than
		/// one, or the <paramref name="cost"/> parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(byte[] password, int saltSize, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(password, GetRandomBytes(saltSize), blockSize, parallelization, cost) {
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt
		/// size, and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="saltSize">
		/// The size of the random salt that you want the class to generate.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="saltSize"/> parameter is less than 1, or the <paramref name="blockSize"/>
		/// parameter is less than one, or the <paramref name="parallelization"/> is less than
		/// one, or the <paramref name="cost"/> parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(string password, int saltSize, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(Encoding.UTF8.GetBytes(password), saltSize, blockSize, parallelization, cost) {
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt,
		/// and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="salt">
		/// The key salt used to derive the key.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter or the <paramref name="salt"/> parameter is
		/// null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="blockSize"/> parameter is less than one, or the
		/// <paramref name="parallelization"/> is less than one, or the <paramref name="cost"/>
		/// parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(string password, byte[] salt, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(Encoding.UTF8.GetBytes(password), salt, blockSize, parallelization, cost) {
		}

		/// <summary>
		/// Returns the pseudo-random key for this object.
		/// </summary>
		/// <param name="cb">
		/// The number of pseudo-random key bytes to generate.
		/// </param>
		/// <returns>
		/// A byte array filled with pseudo-random key bytes.
		/// </returns>
		/// <exception cref="ArgumentOutOfRangeException">
		/// The cb parameter is out of range. This parameter requires a non-negative number.
		/// </exception>
		/// <remarks>
		/// 
		/// </remarks>
		public override byte[] GetBytes(int cb) {
			throw new NotImplementedException();
		}

		/// <summary>
		/// Resets the state of the operation.
		/// </summary>
		/// <remarks>
		/// This method is automatically called if the <see cref="Salt"/>, <see cref="BlockSize"/>,
		/// <see cref="Cost"/> or <see cref="Parallelization"/> parameter is modified.
		/// </remarks>
		public override void Reset() {
			throw new NotImplementedException();
		}

#if UNSAFE
		/// <summary>
		/// Salsa20/8 Core is a round-reduced variant of the Salsa20 Core. It is a hash function
		/// from 64-octet strings to 64-octet strings.
		/// </summary>
		/// <param name="input">
		/// A 64-byte sized array of input data.
		/// </param>
		/// <param name="output">
		/// A pointer to the array to store the transformed data into.
		/// </param>
		/// <returns>
		/// A pointer to the transformed output data.
		/// </returns>
		/// <remarks>
		///  Note that Salsa20/8 Core is not a cryptographic hash function since it is not
		///  collision resistant.
		/// </remarks>
		internal static unsafe uint* Salsa(uint[] input, uint* output) {
			var x = new uint[16];
			for (var i = 0; i < 16; ++i)
				x[i] = input[i];
			for (var i = 8; i > 0; i -= 2) {
				x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
				x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
				x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
				x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
				x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
				x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
				x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
				x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
				x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
				x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
				x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
				x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
				x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
				x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
				x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
				x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
			}
			for (var i = 0; i < 16; ++i)
				output[i] = x[i] + input[i];
			return output;
		}

		/// <summary>
		/// Performs the BlockMix algorithm.
		/// </summary>
		/// <param name="input">
		/// The input data of size 128 * <see cref="BlockSize"/> bytes.
		/// </param>
		/// <returns>
		/// The transformed output data of size 128 * <see cref="BlockSize"/> bytes.
		/// </returns>
		internal static unsafe uint[] ScryptBlockMix(uint[] input) {
			uint[] y = new uint[input.Length],
				   t = new uint[16],
				   z = new uint[16];
			fixed (uint* p = input, py = y, pz = z)
			{
				var x = &p[input.Length - 16];
				for (var i = 0; i < input.Length / 16; i++) {
					for (var c = 0; c < 16; c++)
						t[c] = x[c] ^ p[i * 16 + c];
					x = Salsa(t, pz);
					for (var c = 0; c < 16; c++)
						py[i * 16 + c] = x[c];
				}
			}
			return y;
		}

		/// <summary>
		/// Performs the RomMix algorithm.
		/// </summary>
		/// <param name="input">
		/// The input data of size 128 * <see cref="BlockSize"/> bytes.
		/// </param>
		/// <returns>
		/// The transformed output data of size 128 * <see cref="BlockSize"/> bytes.
		/// </returns>
		internal unsafe uint[] ScryptROMix(uint[] input) {
			var len = input.Length;
			var v = new uint[len * Cost];
			fixed (uint* pv = v)
			{
				for (var i = 0; i < Cost; i++) {
					for (var c = 0; c < len; c++)
						pv[i * len + c] = input[c];
					input = ScryptBlockMix(input);

				}
				for (var i = 0; i < Cost; i++) {
					var j = input[input.Length - 16] % Cost;
					var t = Xor(input, &pv[j * len]);
					input = ScryptBlockMix(t);
				}
			}
			return input;
		}
#else
		/// <summary>
		/// Salsa20/8 Core is a round-reduced variant of the Salsa20 Core. It is a hash function
		/// from 64-octet strings to 64-octet strings.
		/// </summary>
		/// <param name="input">
		/// A 64-byte sized array of input data.
		/// </param>
		/// <returns>
		/// A 64-byte sized array of the transformed output data.
		/// </returns>
		/// <remarks>
		///  Note that Salsa20/8 Core is not a cryptographic hash function since it is not
		///  collision resistant.
		/// </remarks>
		internal static uint[] Salsa(uint[] input) {
			int i;
			var x = new uint[16];
			var output = new uint[16];
			for (i = 0; i < 16; ++i)
				x[i] = input[i];
			for (i = 8; i > 0; i -= 2) {
				x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
				x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
				x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
				x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
				x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
				x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
				x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
				x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
				x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
				x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
				x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
				x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
				x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
				x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
				x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
				x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
			}
			for (i = 0; i < 16; ++i)
				output[i] = x[i] + input[i];
			return output;
		}

		/// <summary>
		/// Performs the BlockMix algorithm.
		/// </summary>
		/// <param name="input">
		/// The input data of size 128 * <see cref="BlockSize"/> bytes.
		/// </param>
		/// <returns>
		/// The transformed output data of size 128 * <see cref="BlockSize"/> bytes.
		/// </returns>
		internal static byte[] ScryptBlockMix(byte[] input) {
			var numBlocks = input.Length / 64;
			var blocks = new uint[numBlocks][];
			for (var i = 0; i < blocks.Length; i++) {
				blocks[i] = new uint[16];
				for (var c = 0; c < 16; c++)
					blocks[i][c] = BitConverter.ToUInt32(input, i * 64 + c * 4);
			}
			var x = blocks[numBlocks - 1];
			var y = new uint[numBlocks][];
			for (var i = 0; i < blocks.Length; i++) {
				var t = Xor(x, blocks[i]);
				x = Salsa(t);
				y[i] = x;
			}
			var @out = new byte[numBlocks * 64];
			for (var i = 0; i < y.Length; i++) {
				for (var c = 0; c < 16; c++) {
					@out[i * 64 + c * 4] = (byte)(y[i][c] >> 0);
					@out[i * 64 + c * 4 + 1] = (byte)(y[i][c] >> 8);
					@out[i * 64 + c * 4 + 2] = (byte)(y[i][c] >> 16);
					@out[i * 64 + c * 4 + 3] = (byte)(y[i][c] >> 24);
				}
			}
			return @out;
		}
#endif

		/// <summary>
		/// XORs the specified input arrays with each other and returns the result.
		/// </summary>
		/// <param name="a">
		/// The first array.
		/// </param>
		/// <param name="b">
		/// The second array.
		/// </param>
		/// <returns>
		/// A new array made up of the elements of a XORed with the elements of b.
		/// </returns>
		static unsafe uint[] Xor(uint[] a, uint* b) {
			var c = new uint[a.Length];
			for (var i = 0; i < a.Length; i++)
				c[i] = a[i] ^ b[i];
			return c;
		}

		/// <summary>
		/// Gets an array of bytes with a cryptographically strong sequence of random values of
		/// the specified size.
		/// </summary>
		/// <param name="size">
		/// The size of the array, in bytes.
		/// </param>
		/// <returns>
		/// An array of bytes with a cryptographically strong sequence of random values of the
		/// specified size.
		/// </returns>
		/// <exception cref="ArgumentException">
		/// The size parameter is less than or equal to 0.
		/// </exception>
		static byte[] GetRandomBytes(int size) {
			if (size <= 0)
				throw new ArgumentException(nameof(size));
			var bytes = new byte[size];
			using (var csp = new RNGCryptoServiceProvider())
				csp.GetBytes(bytes);
			return bytes;
		}

		/// <summary>
		/// Should be inlined hopefully.
		/// </summary>
		static uint R(uint a, int b) {
			return (a << b) | (a >> (32 - b));
		}
	}
}
