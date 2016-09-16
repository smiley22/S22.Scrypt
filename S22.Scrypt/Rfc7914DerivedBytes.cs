using System;
using System.Security.Cryptography;
using System.Text;

namespace S22.Scrypt {
	/// <summary>
	/// Implements the password-based key derivation function scrypt.
	/// </summary>
	public class Rfc7914DerivedBytes : DeriveBytes {
		byte[] buffer;
		int startIndex;
		int endIndex;
		readonly byte[] password;
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
				Reset();
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
				Reset();
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
				Reset();
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
				Reset();
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
			this.password = password;
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
		public override byte[] GetBytes(int cb) {
			if (cb <= 0)
				throw new ArgumentOutOfRangeException(nameof(cb), "This parameter requires a " +
					"non-negative number.");
			var data = new byte[cb];
			var offset = 0;
			var size = endIndex - startIndex;
			if (size > 0) {
				if (cb >= size) {
					Buffer.BlockCopy(buffer, startIndex, data, 0, size);
					startIndex = endIndex = 0;
					offset += size;
				} else {
					Buffer.BlockCopy(buffer, startIndex, data, 0, cb);
					startIndex += cb;
					return data;
				}
			}
			while (offset < cb) {
				var T_block = Scrypt(buffer.Length);
				var remainder = cb - offset;
				if (remainder > buffer.Length) {
					Buffer.BlockCopy(T_block, 0, data, offset, buffer.Length);
					offset += buffer.Length;
				} else {
					Buffer.BlockCopy(T_block, 0, data, offset, remainder);
					offset += remainder;
					Buffer.BlockCopy(T_block, remainder, buffer, startIndex, buffer.Length - remainder);
					endIndex += (buffer.Length - remainder);
					return data;
				}
			}
			return data;
		}

		/// <summary>
		/// Resets the state of the operation.
		/// </summary>
		/// <remarks>
		/// This method is automatically called if the <see cref="Salt"/>, <see cref="BlockSize"/>,
		/// <see cref="Cost"/> or <see cref="Parallelization"/> parameter is modified.
		/// </remarks>
		public override void Reset() {
			buffer = new byte[128 * BlockSize];
			startIndex = endIndex = 0;
		}

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
		/// <param name="data">
		/// A pointer to the input data of size 128 * <see cref="BlockSize"/> bytes.
		/// </param>
		/// <param name="size">
		/// The number of elements in the array pointed to by <paramref name="data"/>.
		/// </param>
		internal static unsafe void ScryptBlockMix(uint* data, int size) {
			uint[]
				t = new uint[16],
				z = new uint[16],
				uneven = new uint[size / 2];
			fixed (uint* pz = z, p = uneven)
			{
				uint* last = data, cur = p;
				var x = &data[size - 16];
				for (var i = 0; i < size / 16; i++) {
					for (var c = 0; c < 16; c++)
						t[c] = x[c] ^ data[i * 16 + c];
					x = Salsa(t, pz);
					var div = i / 2;
					var temp = cur;
					cur = last;
					last = temp;
					for (var c = 0; c < 16; c++)
						cur[div * 16 + c] = x[c];
				}
			}
			for (var i = 0; i < uneven.Length; i++)
				data[uneven.Length + i] = uneven[i];
		}

		/// <summary>
		/// Performs the ROMix algorithm.
		/// </summary>
		/// <param name="data">
		/// A pointer to the input data of size 128 * <see cref="BlockSize"/> bytes.
		/// </param>
		/// <param name="size">
		/// The number of elements in the array pointed to by <paramref name="data"/>.
		/// </param>
		internal unsafe void ScryptROMix(uint* data, int size) {
			var v = new uint[size * Cost];
			fixed (uint* pv = v)
			{
				for (var i = 0; i < Cost; i++) {
					for (var c = 0; c < size; c++)
						pv[i * size + c] = data[c];
					ScryptBlockMix(data, size);
				}
				for (var i = 0; i < Cost; i++) {
					var j = data[size - 16] % Cost;
					for(var k = 0; k < size; k++)
						data[k] ^= pv[j * size + k];
					ScryptBlockMix(data, size);
				}
			}
		}
		 internal unsafe byte[] Scrypt(int dkLen) {
			using (var hmac = new HMACSHA256(password)) {
				using (var rfc = new _Rfc2898DeriveBytes(password, salt, 1, hmac)) {
					var b = rfc.GetBytes(Parallelization * 128 * BlockSize);
					fixed (byte* bp = b)
					{
						var p = (uint*)bp;
						for (var i = 0; i < Parallelization; i++) {
							ScryptROMix(&p[32 * BlockSize * i], 32 * BlockSize);
						}
					}
					using (var rfc2 = new _Rfc2898DeriveBytes(password, b, 1, hmac)) {
						return rfc2.GetBytes(dkLen);
					}
				}
			}
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
