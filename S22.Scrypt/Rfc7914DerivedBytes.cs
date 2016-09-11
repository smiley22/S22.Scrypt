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
				salt = value;
			}
		}

		/// <summary>
		/// Gets or sets the block size parameter for the operation.
		/// </summary>
		/// <remarks>
		/// At the current time (August 2016), a block size of 8 appears to yield good results.
		/// </remarks>
		public int BlockSize {
			get {
				return blockSize;
			}
			set {
				throw new NotImplementedException();
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
		/// value is not a power of 2, or the new value is less then
		/// 2^(128 * <see cref="BlockSize"/> / 8).
		/// </exception>
		public int Cost {
			get {
				return cost;
			}
			set {
				throw new NotImplementedException();
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
		/// The property is being set and the new value is negative, or the new value is bigger
		/// than ((2^32-1) * 32) / (128 * <see cref="BlockSize"/>).
		/// </exception>
		public int Parallelization {
			get {
				return parallelization;
			}
			set {
				throw new NotImplementedException();
			}
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt size, and number of iterations to derive the key.
		/// </summary>
		/// <param name="password"></param>
		/// <param name="salt"></param>
		/// <param name="blockSize"></param>
		/// <param name="parallelization"></param>
		/// <param name="cost"></param>
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
		/// size, and optionally a block size and values to use for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password"></param>
		/// <param name="saltSize"></param>
		/// <param name="blockSize"></param>
		/// <param name="parallelization"></param>
		/// <param name="cost"></param>
		public Rfc7914DerivedBytes(byte[] password, int saltSize, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(password, GetRandomBytes(saltSize), blockSize, parallelization, cost) {
		}

		public Rfc7914DerivedBytes(string password, int saltSize, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(Encoding.UTF8.GetBytes(password), saltSize, blockSize, parallelization, cost) {
		}

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

		byte[] Salsa(byte[] input) {
			throw new NotImplementedException();
		}

		byte[] ScryptBlockMix(byte[] input) {
			throw new NotImplementedException();
		}

		byte[] ScryptROMix(byte[] input) {
			throw new NotImplementedException();
		}

		static byte[] GetRandomBytes(int size) {
			if (size <= 0)
				throw new ArgumentException(nameof(size));
			var bytes = new byte[size];
			using (var csp = new RNGCryptoServiceProvider())
				csp.GetBytes(bytes);
			return bytes;
		}
	}
}
